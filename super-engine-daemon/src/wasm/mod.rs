// SPDX-License-Identifier: GPL-3.0-only
//! Running backends shipped as `wasi:http` proxy components.
//!
//! A [`WasmComponent`] loads a component and drives the `/v1` contract
//! in-process over wasmtime's `wasi:http` host. The product's secrets and
//! options ride as request headers it supplies; outbound egress is confined
//! to the backend's `allowed_hosts` plus the endpoint the user authorized
//! through its `base_url` option (see [`host::AllowlistHooks`]).
//!
//! A websocket-capable backend also imports the realtime `ws` interface and
//! exports `ws-server` ([`realtime`]). Their package is
//! [`REALTIME_PACKAGE`]; a product that published backends under a name of
//! its own before that package existed passes the old name in, and those
//! backends keep loading.

pub mod base_url;
pub mod host;
pub mod realtime;

use std::future::Future;
use std::path::Path;
use std::sync::{Arc, PoisonError, RwLock};

use anyhow::{Context, Result, anyhow, bail};
use http_body_util::BodyExt;
use wasmtime::component::{Component, Linker, Resource, ResourceTable};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::WasiCtx;
use wasmtime_wasi_http::WasiHttpCtx;
use wasmtime_wasi_http::p2::WasiHttpView;
use wasmtime_wasi_http::p2::bindings::ProxyPre;
use wasmtime_wasi_http::p2::bindings::http::types::{ErrorCode, Scheme};
use wasmtime_wasi_http::p2::body::HyperOutgoingBody;

use host::{AllowlistHooks, Host};
use realtime::{ConsumerStreamResource, ConsumerStreamTransport, WsError};

/// The package a websocket-capable backend imports `ws` from and exports
/// `ws-server` from, as `<name>@<version>`.
pub const REALTIME_PACKAGE: &str = "super-engine:realtime@0.1.0";

/// The interfaces a WASM backend may import, by prefix: what its Rust
/// runtime and the `/v1` contract need. `wasi:sockets` and `wasi:filesystem`
/// are not among them, so the only network egress is the allowlisted
/// `wasi:http/outgoing-handler`.
const ALLOWED_IMPORTS: &[&str] = &[
    "wasi:cli/",
    "wasi:http/",
    "wasi:io/",
    "wasi:clocks/",
    "wasi:random/",
];

/// A realtime package, split into its name and version.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Package {
    name: String,
    version: String,
}

impl Package {
    /// Split `<name>@<version>`.
    fn parse(s: &str) -> Result<Self> {
        let (name, version) = s
            .split_once('@')
            .with_context(|| format!("realtime package `{s}` has no `@<version>`"))?;
        Ok(Self {
            name: name.to_string(),
            version: version.to_string(),
        })
    }

    /// The full name of `interface` in this package, as a component names its
    /// imports and exports: `<name>/<interface>@<version>`.
    fn interface(&self, interface: &str) -> String {
        format!("{}/{interface}@{}", self.name, self.version)
    }
}

/// A loaded WASM backend component.
pub struct WasmComponent {
    engine: Engine,
    pre: ProxyPre<Host>,
    /// The package the component's realtime interfaces are under, when it is
    /// websocket-capable.
    realtime: Option<Package>,
    allowed_hosts: Arc<[String]>,
    /// Hosts the *user* authorized via backend options (e.g. a `base_url` set in
    /// the settings UI). Exempt from the SSRF guard — see [`AllowlistHooks`].
    ///
    /// Swappable, unlike [`Self::allowed_hosts`]: the manifest's list can only
    /// change by reinstalling the backend, while this one changes whenever the
    /// user edits the setting. See [`Self::reconfigure`].
    user_allowed_hosts: RwLock<Arc<[String]>>,
    allow_loopback: bool,
    /// The header set injected on every `/v1` request to this backend — the
    /// user's secrets and options. Swappable for the same reason as
    /// [`Self::user_allowed_hosts`], and behind a lock because every request
    /// path holds only `&self`.
    request_headers: RwLock<Vec<(String, String)>>,
}

impl WasmComponent {
    /// Load a component.
    ///
    /// `allowed_hosts` are the backend's manifest-pinned
    /// `[network].allowed_hosts` (SSRF-guarded); `user_allowed_hosts` is what
    /// the user authorized via a `base_url` option, whose `host:port` has the
    /// guard relaxed (see [`host::AllowlistHooks::user_allowed_hosts`]).
    /// `request_headers` are the already-formed secret and option pairs to
    /// inject.
    ///
    /// A `websocket_capability` backend gets the realtime `ws` interface,
    /// under [`REALTIME_PACKAGE`] or whichever of `legacy_realtime_packages`
    /// (`<name>@<version>`) it was built against.
    ///
    /// # Errors
    /// Returns an error if the component cannot be loaded or linked, or
    /// imports an interface a sandboxed backend may not have.
    pub fn load(
        component_path: &Path,
        allowed_hosts: Vec<String>,
        user_allowed_hosts: Vec<String>,
        request_headers: Vec<(String, String)>,
        websocket_capability: bool,
        legacy_realtime_packages: &[&str],
    ) -> Result<Self> {
        let mut config = Config::new();
        config.wasm_component_model(true);
        let engine = Engine::new(&config)?;
        let component = Component::from_file(&engine, component_path)
            .map_err(|e| anyhow!("loading component {}: {e}", component_path.display()))?;

        let mut packages = vec![Package::parse(REALTIME_PACKAGE)?];
        for legacy in legacy_realtime_packages {
            packages.push(Package::parse(legacy)?);
        }
        let realtime = if websocket_capability {
            let Some(package) = realtime_package(&engine, &component, &packages) else {
                bail!(
                    "backend declares the websocket capability but uses no realtime \
                     package this daemon knows"
                );
            };
            Some(package)
        } else {
            None
        };
        verify_imports(&engine, &component, realtime.as_ref())?;

        let mut linker: Linker<Host> = Linker::new(&engine);
        // Link the full wasi command world (the component's Rust std runtime
        // imports `wasi:cli/environment` etc.) plus http. Capabilities remain
        // gated by the locked-down `WasiCtx` below — no preopened directories
        // and no granted sockets — so the component cannot touch the disk or
        // open raw connections; its only egress is the allowlisted
        // `wasi:http/outgoing-handler`.
        // `cli-exit-with-code` is still an `@unstable` WASI 0.2 feature, so
        // `LinkOptions::default()` leaves it out of the linker — but Rust's
        // wasm32-wasip2 std imports it, so every component built with a
        // toolchain that emits that import fails to instantiate unless the
        // host opts in. Enable it so backends stay loadable across toolchains.
        let mut link_options = wasmtime_wasi::p2::bindings::LinkOptions::default();
        link_options.cli_exit_with_code(true);
        wasmtime_wasi::p2::add_to_linker_with_options_async(&mut linker, &link_options)?;
        wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut linker)?;
        // A websocket-capable backend additionally imports the realtime `ws`
        // interface and exports `ws-server`; link the host `ws` impl under the
        // package the component was built against.
        if let Some(package) = &realtime {
            if package.name == Package::parse(REALTIME_PACKAGE)?.name {
                realtime::add_to_linker(&mut linker)?;
            } else {
                realtime::add_to_linker_as(&mut linker, &package.interface("ws"))?;
            }
        }
        let pre = ProxyPre::new(linker.instantiate_pre(&component)?)?;
        Ok(Self {
            engine,
            pre,
            realtime,
            allowed_hosts: allowed_hosts.into(),
            user_allowed_hosts: RwLock::new(user_allowed_hosts.into()),
            allow_loopback: false,
            request_headers: RwLock::new(request_headers),
        })
    }

    /// Permit this backend's egress to loopback addresses (`127.0.0.1`, `::1`).
    ///
    /// The SSRF guard blocks loopback by default so an untrusted backend can't
    /// reach a service bound to localhost. Enable this ONLY for tests or local
    /// development that point the backend at a mock upstream on loopback —
    /// never for an installed/untrusted backend. Only loopback is relaxed;
    /// link-local, private, and the cloud-metadata endpoint stay blocked.
    #[must_use]
    pub fn permit_loopback_egress(mut self) -> Self {
        self.allow_loopback = true;
        self
    }

    /// Whether the component exports the realtime `ws-server`.
    #[must_use]
    pub fn is_realtime(&self) -> bool {
        self.realtime.is_some()
    }

    /// The egress policy every invocation of this backend enforces — the one
    /// place the two lists are wired into the hooks, so the batch and realtime
    /// paths cannot drift into disagreeing about which list is which.
    ///
    /// The distinction is load-bearing: `allowed_hosts` is the backend's own
    /// manifest and stays fully SSRF-guarded, while `user_allowed_hosts` is what
    /// the user authorized and has the guard relaxed for its `host:port`. Wiring
    /// them the other way round would hand a backend the relaxation for hosts it
    /// declared itself.
    ///
    /// The hooks only read the lists, so both are shared rather than copied:
    /// this runs once per request and once per realtime session, and each call
    /// takes whatever the user had authorized at that moment. A session already
    /// running keeps the policy it started with — the check happens on every
    /// outbound connection, but against the list its own store holds.
    #[must_use]
    pub fn allowlist_hooks(&self) -> AllowlistHooks {
        AllowlistHooks {
            allowed_hosts: self.allowed_hosts.clone(),
            user_allowed_hosts: self
                .user_allowed_hosts
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
            allow_loopback: self.allow_loopback,
        }
    }

    /// The secret/option pairs to inject on a request. Cloned so the guard is
    /// dropped before the call.
    #[must_use]
    pub fn request_headers(&self) -> Vec<(String, String)> {
        self.request_headers
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Swap the injected secret/option pairs and the egress the user's
    /// `base_url` authorizes, together, because they came from one snapshot
    /// of the settings and must not disagree about the endpoint.
    ///
    /// Nothing is rebuilt: the `Engine`, the `Component` and its
    /// pre-instantiation are not parameterized by either list, and the `Store`
    /// that carries the egress policy is built fresh for every call anyway. A
    /// call already in flight finishes under the policy it started with.
    pub fn reconfigure(&self, headers: Vec<(String, String)>, user_allowed_hosts: Vec<String>) {
        *self
            .request_headers
            .write()
            .unwrap_or_else(PoisonError::into_inner) = headers;
        *self
            .user_allowed_hosts
            .write()
            .unwrap_or_else(PoisonError::into_inner) = user_allowed_hosts.into();
    }

    /// A fresh store for one call, carrying the egress policy as of now.
    fn store(&self) -> Store<Host> {
        let host = Host {
            table: ResourceTable::new(),
            wasi: WasiCtx::builder().build(),
            http: WasiHttpCtx::new(),
            hooks: self.allowlist_hooks(),
        };
        Store::new(&self.engine, host)
    }

    /// Drive one `/v1` request through the component in-process and return
    /// its `(status, body)`.
    ///
    /// # Errors
    /// Returns an error if the component cannot be invoked or produces no
    /// response.
    pub async fn invoke(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: Vec<u8>,
    ) -> Result<(u16, Vec<u8>)> {
        self.invoke_streaming(method, path, headers, body, |response| async move {
            let status = response.status().as_u16();
            let collected = response.into_body().collect().await?.to_bytes();
            Ok((status, collected.to_vec()))
        })
        .await
    }

    /// Drive one `/v1` request through the component, handing the response to
    /// `read` as soon as the guest publishes its head.
    ///
    /// The guest call and `read` run **concurrently**. A `wasi:http` guest
    /// hands over its response head (`ResponseOutparam::set`) before it starts
    /// writing the body, so awaiting the guest to completion first would
    /// buffer the whole body and make time-to-first-byte equal the total time.
    /// Joining the two lets a caller consume the body while the component is
    /// still producing it.
    ///
    /// # Errors
    /// Returns `read`'s error first — it names what was wrong with the
    /// response, whereas a guest trap on a half-written body is usually the
    /// downstream symptom — then the guest's.
    pub async fn invoke_streaming<R, F, Fut>(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: Vec<u8>,
        read: F,
    ) -> Result<R>
    where
        F: FnOnce(hyper::Response<HyperOutgoingBody>) -> Fut,
        Fut: Future<Output = Result<R>>,
    {
        let mut store = self.store();

        let mut builder = hyper::Request::builder()
            .method(method)
            .uri(format!("http://backend.local{path}"));
        for (key, value) in headers {
            builder = builder.header(key.as_str(), value.as_str());
        }
        let request = builder
            .body(
                http_body_util::Full::new(bytes::Bytes::from(body))
                    .map_err(|never: std::convert::Infallible| -> ErrorCode { match never {} }),
            )
            .context("building backend request")?;

        let (tx, rx) = tokio::sync::oneshot::channel();
        let incoming = store
            .data_mut()
            .http()
            .new_incoming_request(Scheme::Http, request)?;
        let out = store.data_mut().http().new_response_outparam(tx)?;

        // The guest half: runs the component to completion, writing the body
        // as it goes.
        let guest = async {
            let proxy = self.pre.instantiate_async(&mut store).await?;
            proxy
                .wasi_http_incoming_handler()
                .call_handle(&mut store, incoming, out)
                .await
        };

        // The reader half: takes the head as soon as the guest publishes it.
        // It touches no wasmtime state, so it borrows nothing from `store`.
        let reader = async {
            let response = rx
                .await
                .context("backend produced no response")?
                .map_err(|e| anyhow!("backend transport error: {e:?}"))?;
            read(response).await
        };

        let (guest_result, read_result) = tokio::join!(guest, reader);
        let value = read_result?;
        guest_result?;
        Ok(value)
    }

    /// `GET /v1/status` — readiness snapshot.
    ///
    /// # Errors
    /// Returns an error if the component cannot be invoked or its response is
    /// not valid JSON.
    pub async fn status(&self) -> Result<serde_json::Value> {
        let (_, body) = self.invoke("GET", "/v1/status", &[], Vec::new()).await?;
        Ok(serde_json::from_slice(&body)?)
    }

    /// `GET /v1/ping` — liveness.
    ///
    /// # Errors
    /// Returns an error if the component cannot be invoked or its response is
    /// not valid JSON.
    pub async fn ping(&self) -> Result<serde_json::Value> {
        let (_, body) = self.invoke("GET", "/v1/ping", &[], Vec::new()).await?;
        Ok(serde_json::from_slice(&body)?)
    }

    /// Run one consumer realtime session: instantiate the component and invoke
    /// its `ws-server.handle` export with `headers` and a host-owned consumer
    /// stream. Returns when the guest's handler returns.
    ///
    /// # Errors
    /// Returns an error if the backend is not realtime-capable, instantiation
    /// fails, or the guest's handler returns a `ws-error`.
    pub async fn realtime_session(
        &self,
        headers: Vec<(String, Vec<u8>)>,
        transport: ConsumerStreamTransport,
    ) -> Result<()> {
        let Some(package) = &self.realtime else {
            bail!("backend is not websocket-capable");
        };
        let mut store = self.store();
        let consumer = store
            .data_mut()
            .table
            .push(ConsumerStreamResource::new(transport))?;
        let instance = self
            .pre
            .instance_pre()
            .instantiate_async(&mut store)
            .await?;
        let server_name = package.interface("ws-server");
        let server = instance
            .get_export_index(&mut store, None, &server_name)
            .with_context(|| format!("backend exports no `{server_name}`"))?;
        let handle = instance
            .get_export_index(&mut store, Some(&server), "handle")
            .with_context(|| format!("`{server_name}` has no `handle`"))?;
        let handle = instance
            .get_typed_func::<
                (&[(String, Vec<u8>)], Resource<ConsumerStreamResource>),
                (std::result::Result<(), WsError>,),
            >(&mut store, &handle)
            .map_err(|e| anyhow!("`{server_name}.handle` has an unexpected signature: {e}"))?;
        let (result,) = handle.call_async(&mut store, (&headers, consumer)).await?;
        result.map_err(|e| anyhow!("ws-server.handle returned error: {e:?}"))
    }
}

/// Which of `packages` the component's realtime interfaces are under: the
/// one it imports `ws` from or exports `ws-server` under, if any.
fn realtime_package(
    engine: &Engine,
    component: &Component,
    packages: &[Package],
) -> Option<Package> {
    let ty = component.component_type();
    let names: Vec<String> = ty
        .imports(engine)
        .map(|(name, _)| name.to_string())
        .chain(ty.exports(engine).map(|(name, _)| name.to_string()))
        .collect();
    packages
        .iter()
        .find(|p| names.contains(&p.interface("ws")) || names.contains(&p.interface("ws-server")))
        .cloned()
}

/// Reject a component that imports interfaces a sandboxed backend must not
/// have — see [`ALLOWED_IMPORTS`]. A websocket-capable one may also import
/// its realtime package; a non-ws backend simply won't.
fn verify_imports(
    engine: &Engine,
    component: &Component,
    realtime: Option<&Package>,
) -> Result<()> {
    let realtime_prefix = realtime.map(|p| format!("{}/", p.name));
    for (name, _) in component.component_type().imports(engine) {
        let interface = name.split('@').next().unwrap_or(name);
        let allowed = ALLOWED_IMPORTS.iter().any(|p| interface.starts_with(p))
            || realtime_prefix
                .as_deref()
                .is_some_and(|p| interface.starts_with(p));
        if !allowed {
            bail!(
                "backend imports disallowed interface `{name}`: WASM backends \
                 may not access raw sockets or the filesystem"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Package;

    #[test]
    fn a_package_names_its_interfaces() {
        let p = Package::parse("super-engine:realtime@0.1.0").unwrap();
        assert_eq!(p.interface("ws"), "super-engine:realtime/ws@0.1.0");
        assert_eq!(
            p.interface("ws-server"),
            "super-engine:realtime/ws-server@0.1.0"
        );
        assert!(Package::parse("super-engine:realtime").is_err());
    }
}
