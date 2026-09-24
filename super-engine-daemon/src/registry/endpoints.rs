// SPDX-License-Identifier: GPL-3.0-only
//! What the `/registry/backend/*` endpoints do: browse the catalog
//! ([`list`]), re-fetch it ([`refresh`]), describe what a source would install
//! ([`preview`]), install it ([`install`]) and upgrade it ([`update`]).
//!
//! A daemon declares each route itself, with its own path and its own
//! `#[utoipa::path]`, and answers it by calling the function here with its
//! [`Registry`]. Every failure is answered in the [`RegistryError`] envelope.
//!
//! What the daemon supplies is a [`RegistryHost`]: the backends it has
//! installed, the directory they live in, and what to repoint when a backend
//! moves to a new directory.

use std::collections::HashSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use super_engine_spec::forge::Forge;
use super_engine_spec::index::IndexBackend;
use super_engine_spec::product::Product;
use super_engine_spec::registry::events::{InstallError, InstallPhase, RegistryEvent};
use super_engine_spec::registry::{
    Compatibility, InstallAccepted, PreviewResponse, RefreshResponse, RegistryBackend,
    RegistryListResponse, RegistryModel, SelectedAsset, UpdateResponse,
};
use utoipa::ToSchema;

use super::client::Client;
use super::compat::{self, Selection};
use super::{Daemon, custom_repo, host, install_dir_name, local_dir};
use crate::backends::{DiscoveredBackend, installed_version};
use crate::events::CoreEvents;

/// The daemon behind the registry endpoints.
pub trait RegistryHost: Send + Sync + 'static {
    /// The product whose manifests and index entries it reads.
    type Product: Product;
    /// The bus install progress is published on.
    type Events: CoreEvents + 'static;

    /// This daemon, as the registry code knows it.
    fn daemon(&self) -> Daemon;

    /// The bus the `registry_install` events go out on.
    fn events(&self) -> Arc<Self::Events>;

    /// The backends installed here, as of the last scan.
    fn backends(&self) -> &tokio::sync::RwLock<Vec<DiscoveredBackend<Self::Product>>>;

    /// The directory backends install into.
    fn backends_dir(&self) -> impl Future<Output = PathBuf> + Send;

    /// `removed` served the same backend `winner` now serves, and are gone.
    /// Repoint whatever named one of them, such as the active backend, at
    /// `winner`.
    ///
    /// It is the same backend with the same models, only in a new directory,
    /// so a model selection must survive the move.
    fn backend_dirs_replaced(
        &self,
        removed: &[PathBuf],
        winner: &Path,
    ) -> impl Future<Output = ()> + Send;

    /// Scan the backends directory again, so a finished install is served.
    fn refresh_backends(&self) -> impl Future<Output = ()> + Send;
}

type IndexModelOf<H> = <<H as RegistryHost>::Product as Product>::IndexModel;
type Entry<H> = IndexBackend<IndexModelOf<H>>;
type Backend<H> = RegistryBackend<RegistryModel<IndexModelOf<H>>>;

/// What the registry endpoints share: the daemon, its index client, and the
/// installs in flight. A daemon keeps one in its router state; clones share
/// all three.
pub struct Registry<H: RegistryHost> {
    host: Arc<H>,
    client: Arc<Client<IndexModelOf<H>>>,
    /// The `source` of every install or update in flight, so a second one
    /// for the same backend is refused rather than racing the first.
    in_flight: Arc<Mutex<HashSet<String>>>,
}

impl<H: RegistryHost> Clone for Registry<H> {
    fn clone(&self) -> Self {
        Self {
            host: Arc::clone(&self.host),
            client: Arc::clone(&self.client),
            in_flight: Arc::clone(&self.in_flight),
        }
    }
}

impl<H: RegistryHost> Registry<H> {
    #[must_use]
    pub fn new(host: Arc<H>, client: Client<IndexModelOf<H>>) -> Self {
        Self {
            host,
            client: Arc::new(client),
            in_flight: Arc::default(),
        }
    }

    /// The index client.
    #[must_use]
    pub fn client(&self) -> &Client<IndexModelOf<H>> {
        &self.client
    }
}

// ---------------------------------------------------------------------------
// Wire
// ---------------------------------------------------------------------------

/// The registry surface's error envelope, which carries one extra key.
///
/// These endpoints shipped before `error_code` existed, spelling the failure
/// identity as `error`. That key is still sent, because clients read it; the
/// standard `error_code` was added alongside rather than in place of it, so the
/// whole surface honors the "`error_code` on every error" rule without breaking
/// anyone. Both name the same failure and always agree.
///
/// Documented as its own shape rather than folded into a daemon's general
/// error envelope: `error` appears *only* here, and putting it on the shared
/// envelope would tell every other endpoint's reader to expect a key they will
/// never receive.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct RegistryError {
    /// Always `error`.
    #[schema(example = "error")]
    pub status: String,
    /// The stable identifier for this failure.
    #[schema(example = "not_found")]
    pub error_code: String,
    /// The same identifier under the key this surface has always used. Retained
    /// for clients written against it; prefer `error_code`.
    #[schema(example = "not_found")]
    pub error: String,
    /// Human-readable detail, when there is any to add.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// A [`RegistryError`] answer: `code` at `status`.
#[must_use]
pub fn error(status: StatusCode, code: &str) -> Response {
    error_envelope(status, code, None)
}

/// [`error`] with a human-readable `message`.
#[must_use]
pub fn error_with_message(status: StatusCode, code: &str, message: &str) -> Response {
    error_envelope(status, code, Some(message))
}

fn error_envelope(status: StatusCode, code: &str, message: Option<&str>) -> Response {
    json(
        status,
        &RegistryError {
            status: "error".to_owned(),
            error_code: code.to_owned(),
            error: code.to_owned(),
            message: message.map(ToOwned::to_owned),
        },
    )
}

fn json<T: Serialize>(status: StatusCode, body: &T) -> Response {
    (
        status,
        [("content-type", "application/json")],
        serde_json::to_string(body).unwrap_or_default(),
    )
        .into_response()
}

// Failures are boxed so the `Err` variant stays pointer-sized
// (`clippy::result_large_err`).
type ErrResp = Box<Response>;

/// Query parameters for the catalog listing.
#[derive(Deserialize, utoipa::IntoParams)]
pub struct ListQuery {
    /// Include entries this machine cannot run. Off by default, so the catalog
    /// shows what is actually installable here.
    #[serde(default)]
    pub include_incompatible: bool,
    /// Filter by transport — `wasm` or `subprocess`.
    pub kind: Option<String>,
    /// Filter by whether the backend calls out to a network service.
    pub online: Option<bool>,
    /// Case-insensitive substring match over name and description.
    pub q: Option<String>,
}

/// The body of an install or a preview.
///
/// The published shape is `InstallRequest`, which states the three alternatives
/// as alternatives. This is the parse target: one struct with three `Option`s,
/// because the daemon has to tell "two of them were sent" apart from "none was"
/// in order to answer `bad_request` rather than a deserialization failure.
#[derive(Deserialize)]
pub struct InstallBody {
    pub source: Option<String>,
    pub repo_url: Option<String>,
    pub local_path: Option<String>,
    pub forge: Option<Forge>,
}

/// The body of an update.
///
/// The parse target for the shape published as `UpdateRequest`; a missing body
/// is answered `missing_body` rather than surfacing as a deserialization
/// failure, which is why the endpoints take an `Option<Json<_>>`.
#[derive(Deserialize)]
pub struct UpdateBody {
    pub source: String,
}

// ---------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------

/// The catalog, filtered by `query`, with each entry's compatibility with this
/// host and what is installed of it.
///
/// Answers `503 registry_unavailable` when the index cannot be fetched and
/// nothing is cached.
pub async fn list<H: RegistryHost>(registry: &Registry<H>, query: &ListQuery) -> Response {
    let Ok(index) = registry.client.get().await else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "registry_unavailable");
    };

    let daemon = registry.host.daemon();
    let host = host::detect();
    let backends = registry.host.backends().read().await;

    let mut result = Vec::new();
    for entry in &index.backends {
        if !passes_filters(entry, query) {
            continue;
        }

        let sel = compat::select::<H::Product>(&daemon, &host, entry);
        let compatibility = compatibility(entry, &sel);

        // A client-update block is always listed: `include_incompatible` is
        // about hardware this host will never satisfy, and swallowing "your
        // client is too old" behind the same toggle hides the one notice that
        // would tell the user what to do.
        if !compatibility.compatible
            && !compatibility.needs_client_update
            && !query.include_incompatible
        {
            continue;
        }

        result.push(map_entry(
            entry,
            compatibility,
            installed_version_for_source(&backends, &entry.source),
        ));
    }

    json(
        StatusCode::OK,
        &RegistryListResponse {
            schema_version: index.schema_version,
            generated_at: index.generated_at.clone(),
            backends: result,
        },
    )
}

/// Whether `entry` survives the listing's filters.
fn passes_filters<M>(entry: &IndexBackend<M>, query: &ListQuery) -> bool {
    if let Some(ref kind) = query.kind
        && &entry.kind != kind
    {
        return false;
    }
    if let Some(online) = query.online
        && entry.online != online
    {
        return false;
    }
    if let Some(ref search) = query.q {
        let search = search.to_lowercase();
        let in_name = entry.name.to_lowercase().contains(&search);
        let in_description = entry
            .description
            .as_deref()
            .unwrap_or("")
            .to_lowercase()
            .contains(&search);
        if !in_name && !in_description {
            return false;
        }
    }
    true
}

/// How `sel`, the build this host would get of `entry`, reads on the wire.
fn compatibility<M>(entry: &IndexBackend<M>, sel: &Selection) -> Compatibility {
    Compatibility {
        compatible: sel.reason().is_none(),
        selected_asset: compat::to_selected_asset(entry, sel),
        reason: sel.reason().map(ToOwned::to_owned),
        needs_client_update: sel.needs_client_update(),
    }
}

/// The installed version of the backend serving `source`, or `None` when no
/// installed backend claims it.
///
/// The catalog is keyed by `source` because that is the only identifier both
/// sides always carry: the index always has one, and every `backend.toml` must
/// declare one. A directory name does not qualify — it is derived differently
/// depending on which install path produced it, so keying on it silently
/// failed to match anything installed from a custom repo or a local path.
///
/// Re-reads the manifest off disk rather than trusting the cached
/// `DiscoveredBackend::version`, so a version bumped since the last scan is
/// reported; the cached value stands in when that read fails.
fn installed_version_for_source<P: Product>(
    backends: &[DiscoveredBackend<P>],
    source: &str,
) -> Option<String> {
    let b = backends.iter().find(|b| b.source == source)?;
    Some(installed_version::<P>(&b.dir).unwrap_or_else(|| b.version.clone()))
}

/// Whether the index offers something newer than what is installed *and this
/// daemon could install it*.
///
/// The daemon answers this rather than each client re-deriving it: it is the
/// side that reads the installed manifest and owns the index. A backend that is
/// not installed here has no update to offer — it has an *install* — so `None`
/// is `false` rather than "everything is an update".
///
/// `compatible` is part of the answer, not a separate concern. A newer release
/// this host cannot run is not an update the user can take: offering it puts an
/// Update button on a card whose only outcome is `422 incompatible`. The
/// commonest way for that to happen is a release that moved to a contract
/// generation this daemon predates — precisely the case where the user needs to
/// update the daemon, not the backend.
///
/// The comparison itself is the shared semver one, which already refuses a
/// downgrade and refuses to guess at a version it cannot parse.
fn update_available(installed: Option<&str>, index_version: &str, compatible: bool) -> bool {
    compatible
        && installed.is_some_and(|i| super_engine_spec::version::update_available(i, index_version))
}

/// `entry` as the listing shows it.
fn map_entry<M: Clone>(
    entry: &IndexBackend<M>,
    compatibility: Compatibility,
    installed_version: Option<String>,
) -> RegistryBackend<RegistryModel<M>> {
    RegistryBackend {
        id: entry.id.clone(),
        backend_id: entry.backend_id.clone(),
        source: entry.source.clone(),
        version: entry.version.clone(),
        name: entry.name.clone(),
        description: entry.description.clone(),
        license: entry.license.clone(),
        kind: entry.kind.clone(),
        contract: entry.contract.clone(),
        min_client: entry.min_client.clone(),
        allowed_hosts: entry.allowed_hosts.clone(),
        online: entry.online,
        supports_gpu: entry.supports_gpu,
        supports_cpu: entry.supports_cpu,
        models: entry
            .models
            .iter()
            .map(|m| RegistryModel {
                name: m.name.clone(),
                // Compatibility shim; see `IndexModel::provider`. Clients
                // through v0.2.0 require the key to parse this response.
                provider: String::new(),
                supported_devices: m.supported_devices.clone(),
                product: m.product.clone(),
            })
            .collect(),
        secrets: entry.secrets.clone(),
        options: entry.options.clone(),
        update_available: update_available(
            installed_version.as_deref(),
            &entry.version,
            compatibility.compatible,
        ),
        compatibility,
        installed_version,
        index_stale: entry.index_stale.clone(),
    }
}

/// Re-fetch the index now rather than when its cache expires, and announce the
/// outcome on the `registry_install` topic so every client learns the catalog
/// moved.
///
/// Answers `503 registry_unavailable` when the fetch fails.
pub async fn refresh<H: RegistryHost>(registry: &Registry<H>) -> Response {
    let events = registry.host.events();
    if let Ok(index) = registry.client.refresh().await {
        publish(
            &*events,
            &RegistryEvent::RefreshCompleted {
                generated_at: index.generated_at.clone(),
                backend_count: index.backends.len(),
            },
        );
        json(
            StatusCode::OK,
            &RefreshResponse {
                schema_version: index.schema_version,
                generated_at: index.generated_at.clone(),
                backend_count: index.backends.len(),
            },
        )
    } else {
        publish(
            &*events,
            &RegistryEvent::RefreshFailed {
                error: "registry_unavailable".to_owned(),
            },
        );
        error(StatusCode::SERVICE_UNAVAILABLE, "registry_unavailable")
    }
}

fn publish<E: CoreEvents + ?Sized>(events: &E, event: &RegistryEvent) {
    events.publish_registry_install(serde_json::to_value(event).unwrap_or_default());
}

// ---------------------------------------------------------------------------
// Resolving an install source
// ---------------------------------------------------------------------------

/// Parse an install body: exactly one of `source`, `repo_url` and
/// `local_path`. Returns the body and whichever of the three was sent.
fn parse_install_body(raw: Option<Json<InstallBody>>) -> Result<(InstallBody, String), ErrResp> {
    let Some(Json(body)) = raw else {
        return Err(Box::new(error(StatusCode::BAD_REQUEST, "missing_body")));
    };

    let key = match (&body.source, &body.repo_url, &body.local_path) {
        (Some(key), None, None) | (None, Some(key), None) | (None, None, Some(key)) => key.clone(),
        _ => {
            return Err(Box::new(error_with_message(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "provide exactly one of source, repo_url, local_path",
            )));
        }
    };
    Ok((body, key))
}

/// The index entry `body` names: from the registry, a forge repository, or a
/// directory staged on this machine.
async fn resolve_install_entry<H: RegistryHost>(
    registry: &Registry<H>,
    body: &InstallBody,
) -> Result<Entry<H>, ErrResp> {
    if let Some(ref source) = body.source {
        let Ok(index) = registry.client.get().await else {
            return Err(Box::new(error(
                StatusCode::SERVICE_UNAVAILABLE,
                "registry_unavailable",
            )));
        };
        return index
            .backends
            .into_iter()
            .find(|b| &b.source == source)
            .ok_or_else(|| Box::new(error(StatusCode::NOT_FOUND, "not_found")));
    }
    if let Some(ref repo_url) = body.repo_url {
        let forge = install_forge(body.forge, repo_url).map_err(|(status, code, message)| {
            Box::new(error_with_message(status, code, &message))
        })?;
        let client = super_engine_forge::client(forge, registry.host.daemon().user_agent);
        return custom_repo::resolve::<H::Product>(client.as_ref(), repo_url)
            .await
            .map_err(|e| {
                let (status, code) = custom_repo_error(&e);
                Box::new(error_with_message(status, code, &e.to_string()))
            });
    }
    let path = Path::new(body.local_path.as_deref().unwrap_or_default());
    local_dir::resolve::<H::Product>(path).map_err(|e| {
        let (status, code) = local_dir_error(&e);
        Box::new(error_with_message(status, code, &e.to_string()))
    })
}

/// The forge to query for a Custom-repo install: whichever one the client
/// declared, else the one serving the host in `repo_url`.
///
/// A pasted repository URL already names its host, and an Add-a-backend sheet
/// has no second thing to ask the operator for, so requiring `forge` alongside
/// it made that install path unusable from an app rather than safer. Falling
/// back to *a* forge would be the unsafe move — the GitHub adapter ignores
/// `RepoRef::host` and would query `api.github.com` for a GitLab URL's
/// owner/repo — so an unserved host is a hard error here, and declaring `forge`
/// stays the way to reach one (GitHub Enterprise via `GITHUB_API_BASE`).
/// `registry.toml` entries are unaffected: an entry author still declares
/// `forge`, and the indexer never infers it.
///
/// # Errors
/// The status and error code to answer with, and the message to put beside
/// them: `bad_repo_url` when `repo_url` is not a `<host>/<owner>/<repo>`
/// reference, `unsupported_forge` when no adapter serves its host.
fn install_forge(
    declared: Option<Forge>,
    repo_url: &str,
) -> Result<Forge, (StatusCode, &'static str, String)> {
    if let Some(forge) = declared {
        return Ok(forge);
    }
    // Parsed here only to read the host; `custom_repo::resolve` parses again
    // for its own use. The failure routes through the same mapping it would
    // have, so a malformed URL answers identically whether or not `forge` was
    // declared.
    let repo = super_engine_forge::RepoRef::parse(repo_url).map_err(|_| {
        let e = custom_repo::ResolveError::BadRepoUrl(repo_url.to_owned());
        let (status, code) = custom_repo_error(&e);
        (status, code, e.to_string())
    })?;
    super_engine_forge::forge_for_host(&repo.host).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "unsupported_forge",
            format!(
                "no forge adapter serves `{}`; declare `forge` to pick one",
                repo.host
            ),
        )
    })
}

/// The status and error code a failed Custom-repo resolution answers with.
fn custom_repo_error(e: &custom_repo::ResolveError) -> (StatusCode, &'static str) {
    use custom_repo::ResolveError;
    match e {
        ResolveError::BadRepoUrl(_) => (StatusCode::BAD_REQUEST, "bad_repo_url"),
        ResolveError::ManifestTooLarge => (StatusCode::UNPROCESSABLE_ENTITY, "manifest_too_large"),
        ResolveError::NotUtf8(_)
        | ResolveError::Manifest(_)
        | ResolveError::MissingWasmAsset
        | ResolveError::MissingSubprocessAssets
        | ResolveError::UnsafeComponent { .. } => {
            (StatusCode::UNPROCESSABLE_ENTITY, "manifest_invalid")
        }
        ResolveError::SourceSpoof { .. } => (StatusCode::UNPROCESSABLE_ENTITY, "source_mismatch"),
        ResolveError::NoRelease { .. } => (StatusCode::NOT_FOUND, "not_found"),
        ResolveError::AssetMissing(_) => (StatusCode::UNPROCESSABLE_ENTITY, "asset_missing"),
        ResolveError::Forge(err) => {
            // 404 from the forge means the repo, release, or backend.toml at the
            // tag is missing — surface as not_found rather than a generic 502.
            if err.http_status() == Some(reqwest::StatusCode::NOT_FOUND) {
                (StatusCode::NOT_FOUND, "not_found")
            } else {
                (StatusCode::BAD_GATEWAY, "forge_unavailable")
            }
        }
    }
}

/// The status and error code a failed Import-from-dir resolution answers with.
fn local_dir_error(e: &local_dir::ResolveError) -> (StatusCode, &'static str) {
    use local_dir::ResolveError;
    match e {
        ResolveError::NotAbsolute(_) => (StatusCode::BAD_REQUEST, "bad_local_path"),
        ResolveError::NotFound(_)
        | ResolveError::NoManifest(_)
        | ResolveError::NoEntrypoint(..) => (StatusCode::NOT_FOUND, "not_found"),
        ResolveError::NotADirectory(_) => (StatusCode::UNPROCESSABLE_ENTITY, "bad_local_path"),
        ResolveError::Manifest(_) | ResolveError::UnsafeId(_) => {
            (StatusCode::UNPROCESSABLE_ENTITY, "manifest_invalid")
        }
    }
}

/// The "selected asset" of a local import: nothing was selected, the operator
/// staged the bytes, and `accel = "local"` records how they landed on disk.
fn local_asset() -> SelectedAsset {
    SelectedAsset {
        target: String::new(),
        accel: vec!["local".into()],
        cuda_major: None,
        cuda_sm: None,
        cudnn: false,
    }
}

/// The `warning` an install from outside the registry carries.
fn unverified_source(body: &InstallBody) -> Option<String> {
    (body.repo_url.is_some() || body.local_path.is_some()).then(|| "unverified_source".to_owned())
}

/// Describe what `body` would install, without installing it: the same
/// resolution as [`install`], answered in the listing's shape.
///
/// Nothing is written and nothing is downloaded beyond the manifest needed to
/// answer. Unlike an install, a host that cannot run the backend is not an
/// error: "this machine cannot run it" is the most useful thing a preview can
/// say, and saying it needs the entry, not a `422`.
pub async fn preview<H: RegistryHost>(
    registry: &Registry<H>,
    body: Option<Json<InstallBody>>,
) -> Response {
    let (body, _) = match parse_install_body(body) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    // Same resolution as an install, so a preview that succeeds and an install
    // that fails cannot disagree about what the source is.
    let entry = match resolve_install_entry(registry, &body).await {
        Ok(e) => e,
        Err(r) => return *r,
    };

    let compatibility = if body.local_path.is_some() {
        // A local import has no published asset to match against this host:
        // the only build in play is the one on disk.
        Compatibility {
            compatible: true,
            selected_asset: Some(local_asset()),
            reason: None,
            needs_client_update: false,
        }
    } else {
        let sel = compat::select::<H::Product>(&registry.host.daemon(), &host::detect(), &entry);
        compatibility(&entry, &sel)
    };

    let installed = {
        let backends = registry.host.backends().read().await;
        installed_version_for_source(&backends, &entry.source)
    };

    json(
        StatusCode::OK,
        &PreviewResponse::<Backend<H>> {
            backend: map_entry(&entry, compatibility, installed),
            warning: unverified_source(&body),
        },
    )
}

// ---------------------------------------------------------------------------
// Install and update
// ---------------------------------------------------------------------------

/// Removes a `source` from the in-flight set when dropped, unless
/// [`defuse`](Self::defuse)d. Held across an endpoint's synchronous checks, so
/// every early error answer releases the `source` without a hand-written
/// removal at each return. These checks fail with plain HTTP errors, not
/// `Failed` install events.
struct InFlightMarker {
    in_flight: Arc<Mutex<HashSet<String>>>,
    source: String,
    armed: bool,
}

impl InFlightMarker {
    /// Mark `source` in flight, or `None` when it already was. The check and
    /// the insert are one step under the lock.
    fn acquire(in_flight: &Arc<Mutex<HashSet<String>>>, source: &str) -> Option<Self> {
        if !in_flight.lock().insert(source.to_owned()) {
            return None;
        }
        Some(Self {
            in_flight: Arc::clone(in_flight),
            source: source.to_owned(),
            armed: true,
        })
    }

    /// Hand the removal to the spawned pipeline's [`InFlightGuard`].
    fn defuse(mut self) {
        self.armed = false;
    }
}

impl Drop for InFlightMarker {
    fn drop(&mut self) {
        if self.armed {
            self.in_flight.lock().remove(&self.source);
        }
    }
}

/// Makes a spawned install reach a terminal state. On the happy path the task
/// [`disarm`](Self::disarm)s it after publishing its own `Completed` or
/// `Failed`. Should the task unwind first, `Drop` releases the `source`, so a
/// retry is not refused with a stale `409`, and publishes `Failed`, so a
/// client's progress bar does not spin forever.
struct InFlightGuard<E: CoreEvents + ?Sized> {
    in_flight: Arc<Mutex<HashSet<String>>>,
    events: Arc<E>,
    install_id: String,
    source: String,
    armed: bool,
}

impl<E: CoreEvents + ?Sized> InFlightGuard<E> {
    /// Normal completion: release the `source` and publish nothing.
    fn disarm(mut self) {
        self.in_flight.lock().remove(&self.source);
        self.armed = false;
    }
}

impl<E: CoreEvents + ?Sized> Drop for InFlightGuard<E> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.in_flight.lock().remove(&self.source);
        publish(
            &*self.events,
            &RegistryEvent::Failed {
                install_id: self.install_id.clone(),
                source: self.source.clone(),
                phase: InstallPhase::Installing,
                error: InstallError::InstallIoError,
            },
        );
    }
}

/// The build of `entry` to install, or `422 incompatible` with the reason
/// [`compat::select`] gave. A local import (`local_src`) selects nothing: its
/// bytes are already on disk.
fn select_install<H: RegistryHost>(
    registry: &Registry<H>,
    entry: &Entry<H>,
    local_src: Option<&Path>,
) -> Result<(Selection, SelectedAsset), ErrResp> {
    if local_src.is_some() {
        // `run_local` ignores the selection.
        return Ok((Selection::Wasm, local_asset()));
    }
    let sel = compat::select::<H::Product>(&registry.host.daemon(), &host::detect(), entry);
    let Some(asset) = compat::to_selected_asset(entry, &sel) else {
        return Err(Box::new(incompatible(&sel)));
    };
    Ok((sel, asset))
}

/// `422 incompatible`, saying why. `select` already worked out the reason, and
/// the reason is the whole value of the check when the remedy is updating the
/// daemon.
fn incompatible(sel: &Selection) -> Response {
    error_with_message(
        StatusCode::UNPROCESSABLE_ENTITY,
        "incompatible",
        sel.reason().unwrap_or("no compatible asset for this host"),
    )
}

/// Install the backend `body` names, in the background.
///
/// Answers `202` with an `install_id` as soon as the build is chosen; the
/// download, verification and install follow on the `registry_install` topic,
/// keyed by it. Events are keyed by what the client sent (a registry source, a
/// repo URL or a local path), so a client tracking an install under what it
/// sent stays in step; the canonical `source` is in the answer.
pub async fn install<H: RegistryHost>(
    registry: &Registry<H>,
    body: Option<Json<InstallBody>>,
) -> Response {
    let (body, key) = match parse_install_body(body) {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let Some(marker) = InFlightMarker::acquire(&registry.in_flight, &key) else {
        return error(StatusCode::CONFLICT, "install_in_progress");
    };
    let entry = match resolve_install_entry(registry, &body).await {
        Ok(e) => e,
        Err(r) => return *r,
    };
    let local_src = body.local_path.as_deref().map(PathBuf::from);
    let (sel, selected_asset) = match select_install(registry, &entry, local_src.as_deref()) {
        Ok(v) => v,
        Err(r) => return *r,
    };

    let install_id = new_install_id();
    let accepted = InstallAccepted {
        install_id: install_id.clone(),
        source: entry.source.clone(),
        version: entry.version.clone(),
        selected_asset,
        warning: unverified_source(&body),
    };
    spawn_pipeline(registry, entry, sel, install_id, key, local_src);
    marker.defuse();

    json(StatusCode::ACCEPTED, &accepted)
}

/// Upgrade the installed backend serving `body.source` to the newest version
/// the catalog offers, in the background.
///
/// Only a strictly newer semver is an upgrade: anything else answers `200`
/// with `noop` and no `install_id`. An upgrade answers `202`, and follows on
/// the `registry_install` topic like an install.
pub async fn update<H: RegistryHost>(
    registry: &Registry<H>,
    body: Option<Json<UpdateBody>>,
) -> Response {
    let Some(Json(body)) = body else {
        return error(StatusCode::BAD_REQUEST, "missing_body");
    };
    let Some(marker) = InFlightMarker::acquire(&registry.in_flight, &body.source) else {
        return error(StatusCode::CONFLICT, "update_in_progress");
    };

    let Ok(index) = registry.client.get().await else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "registry_unavailable");
    };
    let Some(entry) = index.backends.into_iter().find(|b| b.source == body.source) else {
        return error(StatusCode::NOT_FOUND, "not_found");
    };
    // Matched by `source`, the same key the listing uses to decide
    // `update_available`, and the same helper, so the two never drift.
    let installed = {
        let backends = registry.host.backends().read().await;
        installed_version_for_source(&backends, &entry.source)
    };
    let Some(from_version) = installed else {
        return error(StatusCode::NOT_FOUND, "not_installed");
    };

    // String equality would treat any different string as an update, so an
    // older or reformatted index version would "update" into a downgrade.
    if !super_engine_spec::version::update_available(&from_version, &entry.version) {
        return json(
            StatusCode::OK,
            &UpdateResponse {
                install_id: None,
                to_version: from_version.clone(),
                from_version,
                noop: true,
            },
        );
    }

    let sel = match select_install(registry, &entry, None) {
        Ok((sel, _)) => sel,
        Err(r) => return *r,
    };

    let install_id = new_install_id();
    let to_version = entry.version.clone();
    spawn_pipeline(registry, entry, sel, install_id.clone(), body.source, None);
    marker.defuse();

    json(
        StatusCode::ACCEPTED,
        &UpdateResponse {
            install_id: Some(install_id),
            from_version,
            to_version,
            noop: false,
        },
    )
}

fn new_install_id() -> String {
    format!("ins_{}", ulid::Ulid::new())
}

/// Run the install of `entry` in the background. The caller has marked
/// `source` in flight; the task takes over releasing it.
///
/// `local_src` is the staged directory of a local import, and `None` for
/// every other route.
fn spawn_pipeline<H: RegistryHost>(
    registry: &Registry<H>,
    entry: Entry<H>,
    sel: Selection,
    install_id: String,
    source: String,
    local_src: Option<PathBuf>,
) {
    let host = Arc::clone(&registry.host);
    let in_flight = Arc::clone(&registry.in_flight);
    tokio::spawn(async move {
        let events = host.events();
        // Always reach a terminal state, even if the pipeline panics.
        let guard = InFlightGuard {
            in_flight,
            events: Arc::clone(&events),
            install_id: install_id.clone(),
            source: source.clone(),
            armed: true,
        };
        let daemon = host.daemon();
        let progress_events = Arc::clone(&events);
        let progress_id = install_id.clone();
        let progress_source = source.clone();
        let pipeline = super::install::Pipeline {
            backends_dir: host.backends_dir().await,
            cache_dir: super_engine_protocol::paths::cache_dir(daemon.product).join("install"),
            // Bundles can be multi-GB (e.g. a CUDA backend's multi-part
            // archive), so use the generous-timeout download client; the
            // connect timeout still fails fast on an unreachable host.
            http: super_engine_forge::http::download_client(daemon.user_agent),
            on_progress: Arc::new(move |phase, bytes: Option<(u64, Option<u64>)>| {
                let (bytes_done, bytes_total) = bytes.map_or((None, None), |(d, t)| (Some(d), t));
                publish(
                    &*progress_events,
                    &RegistryEvent::Progress {
                        install_id: progress_id.clone(),
                        source: progress_source.clone(),
                        phase,
                        bytes_done,
                        bytes_total,
                    },
                );
            }),
        };

        let outcome = match local_src.as_deref() {
            Some(src) => super::install::run_local::<H::Product, _>(&pipeline, &entry, src).await,
            None => super::install::run::<H::Product, _>(&pipeline, &entry, &sel).await,
        };
        let event = match outcome {
            Ok(version) => {
                // An update that installs a version declaring an `id` may land
                // at a new directory name while the backend is still installed
                // under its old one: retire the predecessor, and move whatever
                // named it, before the catalog is rescanned.
                let dir_name = install_dir_name(&entry);
                retire_and_repoint(&*host, &pipeline.backends_dir, &entry.source, dir_name).await;
                host.refresh_backends().await;
                RegistryEvent::Completed {
                    install_id,
                    source,
                    version,
                }
            }
            Err((phase, error)) => RegistryEvent::Failed {
                install_id,
                source,
                phase,
                error,
            },
        };
        publish(&*events, &event);
        guard.disarm();
    });
}

/// After an install into `backends_dir/dir_name`, retire the directory that
/// used to serve `source`, if the install moved it to a new name, and have the
/// host repoint whatever named the old one.
///
/// The repoint follows the predecessor being *found*, not its removal
/// succeeding: the new directory is the live one either way. Should a
/// concurrent rescan reconcile the predecessor away first, there is nothing
/// left to find here, and the reconciliation repoints instead.
pub async fn retire_and_repoint<H: RegistryHost>(
    host: &H,
    backends_dir: &Path,
    source: &str,
    dir_name: &str,
) {
    let installed_at = backends_dir.join(dir_name);
    let Some(old) =
        super::install::retire_previous_dir::<H::Product>(backends_dir, source, &installed_at)
            .await
    else {
        return;
    };
    host.backend_dirs_replaced(&[old], &installed_at).await;
}

#[cfg(test)]
#[path = "endpoints_tests.rs"]
mod tests;
