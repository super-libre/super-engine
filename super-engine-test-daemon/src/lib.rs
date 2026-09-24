// SPDX-License-Identifier: GPL-3.0-only
//! A product's daemon, spawned for an integration test.
//!
//! [`TestDaemon::start`] runs the daemon binary as a child process in a home
//! of its own and waits until its socket answers. Dropping the handle stops
//! the daemon the way anything else stops one ([`shutdown`]) and removes the
//! home.
//!
//! The home is what keeps a test off the machine it runs on. Config, data and
//! cache each get a directory of their own, so a test daemon neither reads
//! nor writes the developer's `daemon.toml`, installed backends or registry
//! cache, and daemons spawned side by side by one test binary do not
//! overwrite each other's files.
//!
//! The daemon also starts with its product's test switches on:
//!
//! - `<PREFIX>_KEYRING_MOCK=1`: session tokens and secrets live in memory, so
//!   no keyring prompt can stall the suite.
//! - `<PREFIX>_AUTO_APPROVE=1`: a token request is granted without the
//!   consent dialog.
//! - `<PREFIX>_MUTE_CUES=1`: no audio cue plays through the speakers of
//!   whoever runs the tests.
//! - `GITHUB_API_BASE` points at a port nothing listens on, so the update
//!   check the daemon runs at startup fails at once instead of calling the
//!   real API.
//!
//! [`Builder::env`] adds to these or overrides one, and [`Builder::without`]
//! drops one. Set `SUPER_ENGINE_TEST_DAEMON_LOG=1` to see the daemon's own
//! output.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::body::Bytes;
use hyper::client::conn::http1::handshake;
pub use hyper::{Method, StatusCode};
use super_engine_protocol::ProductSpec;
use tokio::net::UnixStream;

/// How long a daemon gets to start answering on its socket.
const READY_TIMEOUT: Duration = Duration::from_mins(2);

/// How often to try the socket while waiting for it.
const READY_POLL: Duration = Duration::from_millis(100);

/// How long a daemon gets to finish its graceful shutdown before it is sent
/// `SIGKILL`, so a wedged child cannot hang the suite.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// How often to check whether the child has exited while waiting.
const SHUTDOWN_POLL: Duration = Duration::from_millis(25);

/// Where nothing listens. `accept_base_url` allows a loopback `http://`
/// address, so the daemon takes it, and the connection is refused at once.
const UNREACHABLE_API: &str = "http://127.0.0.1:9";

/// The variable that shows a test daemon's output.
pub const LOG_VAR: &str = "SUPER_ENGINE_TEST_DAEMON_LOG";

/// The directories a test daemon lives in, all under one root that is
/// removed with it.
#[derive(Debug, Clone)]
pub struct Home {
    root: PathBuf,
    /// `XDG_CONFIG_HOME`: `<config>/<slug>/daemon.toml` is the daemon's
    /// config.
    pub config: PathBuf,
    /// `XDG_DATA_HOME`: installed backends live under it.
    pub data: PathBuf,
    /// `XDG_CACHE_HOME`: the registry index and install downloads.
    pub cache: PathBuf,
}

impl Home {
    fn new(product: &ProductSpec, label: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "{}-{label}-{}-{}",
            product.slug,
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let home = Self {
            config: root.join("config"),
            data: root.join("data"),
            cache: root.join("cache"),
            root,
        };
        for dir in [&home.config, &home.data, &home.cache] {
            std::fs::create_dir_all(dir).expect("create a test daemon's home");
        }
        home
    }

    /// The root the other directories are under.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// A test daemon to be started. See [`TestDaemon::build`].
#[must_use = "a builder does nothing until `start`"]
pub struct Builder {
    product: &'static ProductSpec,
    bin: PathBuf,
    home: Home,
    socket: PathBuf,
    /// `None` removes a variable the daemon would otherwise inherit.
    env: BTreeMap<OsString, Option<OsString>>,
}

impl Builder {
    /// Set `key` for the daemon, replacing any default.
    pub fn env(mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        self.env
            .insert(key.as_ref().to_owned(), Some(value.as_ref().to_owned()));
        self
    }

    /// Start the daemon without `key`, whether it is one of the defaults or
    /// set in the test's own environment.
    pub fn without(mut self, key: impl AsRef<OsStr>) -> Self {
        self.env.insert(key.as_ref().to_owned(), None);
        self
    }

    /// Put the socket at `path` rather than in the daemon's home: for a test
    /// that starts a second daemon where a first one was, to see a client
    /// reconnect.
    pub fn socket_at(mut self, path: impl Into<PathBuf>) -> Self {
        self.socket = path.into();
        let key = OsString::from(self.product.env("HTTP_SOCKET"));
        self.env
            .insert(key, Some(self.socket.as_os_str().to_owned()));
        self
    }

    /// Leave the socket where the daemon puts it when told nothing, for a test
    /// of that default: `<PREFIX>_HTTP_SOCKET` is removed, and
    /// `XDG_RUNTIME_DIR` is a directory in the home, so the socket is
    /// `<runtime>/<short_name>/<socket_file>`.
    ///
    /// # Panics
    ///
    /// If the runtime directory cannot be created.
    pub fn default_socket(mut self) -> Self {
        let runtime = self.home.root.join("runtime");
        let dir = runtime.join(self.product.short_name);
        std::fs::create_dir_all(&dir).expect("create a test daemon's runtime directory");
        self.socket = dir.join(self.product.socket_file());
        self.env
            .insert(OsString::from(self.product.env("HTTP_SOCKET")), None);
        self.env.insert(
            OsString::from("XDG_RUNTIME_DIR"),
            Some(runtime.into_os_string()),
        );
        self
    }

    /// The daemon's home, so a test can lay out files before it starts: a
    /// backend to discover, a config to load.
    #[must_use]
    pub fn home(&self) -> &Home {
        &self.home
    }

    /// The path its HTTP socket will be at.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Spawn the daemon and wait until its socket answers.
    ///
    /// # Panics
    ///
    /// If the binary cannot be spawned, or its socket does not answer within
    /// two minutes. The daemon is stopped and its home removed either way.
    pub async fn start(self) -> TestDaemon {
        let mut command = Command::new(&self.bin);
        for (key, value) in &self.env {
            match value {
                Some(value) => command.env(key, value),
                None => command.env_remove(key),
            };
        }
        if std::env::var_os(LOG_VAR).is_none() {
            command.stdout(Stdio::null()).stderr(Stdio::null());
        }
        let child = command
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {}: {e}", self.bin.display()));

        // Held before the wait, so a daemon that never answers is still
        // stopped and its home removed when the panic below unwinds.
        let daemon = TestDaemon {
            child,
            product: self.product,
            socket: self.socket,
            home: self.home,
        };
        daemon.wait_until_ready().await;
        daemon
    }
}

/// A running test daemon. Dropping it stops the daemon and removes its home.
pub struct TestDaemon {
    child: Child,
    product: &'static ProductSpec,
    socket: PathBuf,
    home: Home,
}

impl TestDaemon {
    /// A daemon of `product`, from the binary at `bin`, with the home and
    /// switches the [crate docs](crate) describe. `label` names its home, so
    /// a leftover one says which test left it.
    ///
    /// In a daemon crate's own tests the binary is
    /// `env!("CARGO_BIN_EXE_<name>")`.
    pub fn build(product: &'static ProductSpec, bin: impl AsRef<Path>, label: &str) -> Builder {
        let home = Home::new(product, label);
        let socket = home.root.join("http.sock");
        let mut env = BTreeMap::new();
        let mut set = |key: String, value: &OsStr| {
            env.insert(OsString::from(key), Some(value.to_owned()));
        };
        set(product.env("KEYRING_MOCK"), OsStr::new("1"));
        set(product.env("AUTO_APPROVE"), OsStr::new("1"));
        set(product.env("MUTE_CUES"), OsStr::new("1"));
        set(product.env("HTTP_SOCKET"), socket.as_os_str());
        set("XDG_CONFIG_HOME".to_owned(), home.config.as_os_str());
        set("XDG_DATA_HOME".to_owned(), home.data.as_os_str());
        set("XDG_CACHE_HOME".to_owned(), home.cache.as_os_str());
        set("GITHUB_API_BASE".to_owned(), OsStr::new(UNREACHABLE_API));
        Builder {
            product,
            bin: bin.as_ref().to_owned(),
            home,
            socket,
            env,
        }
    }

    /// [`build`](Self::build) and [`start`](Builder::start), for a test that
    /// needs nothing else.
    pub async fn start(product: &'static ProductSpec, bin: impl AsRef<Path>, label: &str) -> Self {
        Self::build(product, bin, label).start().await
    }

    /// Its HTTP socket.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Its home.
    #[must_use]
    pub fn home(&self) -> &Home {
        &self.home
    }

    /// Where it discovers installed backends: `<data>/<slug>/backends`.
    #[must_use]
    pub fn backends_dir(&self) -> PathBuf {
        backends_dir(self.product, &self.home)
    }

    /// The child process, for a test that signals it itself.
    pub fn child(&mut self) -> &mut Child {
        &mut self.child
    }

    /// Stop it now rather than on drop. See [`shutdown`].
    pub fn stop(&mut self) {
        shutdown(&mut self.child);
    }

    /// A session token for `scopes`, granted without a dialog.
    ///
    /// # Panics
    ///
    /// If the daemon refuses, which it only does for a scope it does not
    /// know, or when started [`without`](Builder::without) auto-approval.
    pub async fn token(&self, app_name: &str, scopes: &[&str]) -> String {
        super_engine_client::http_client::auth_request(self.socket.clone(), app_name, scopes)
            .await
            .unwrap_or_else(|e| panic!("a token for {scopes:?}: {e}"))
            .session_token
    }

    /// `GET /v1{path}`.
    pub async fn get(&self, path: &str, token: &str) -> (StatusCode, serde_json::Value) {
        self.request(Method::GET, path, Some(token), None).await
    }

    /// `POST /v1{path}` with `body` as JSON.
    pub async fn post(
        &self,
        path: &str,
        token: &str,
        body: &serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        self.request(Method::POST, path, Some(token), Some(body))
            .await
    }

    /// `POST /v1{path}` with no body at all: no `content-type`, no bytes.
    pub async fn post_empty(&self, path: &str, token: &str) -> (StatusCode, serde_json::Value) {
        self.request(Method::POST, path, Some(token), None).await
    }

    /// `DELETE /v1{path}`.
    pub async fn delete(&self, path: &str, token: &str) -> (StatusCode, serde_json::Value) {
        self.request(Method::DELETE, path, Some(token), None).await
    }

    /// `method /v1{path}`, with a bearer `token` and a JSON `body` when given.
    /// Answers with the status and the body parsed as JSON, `null` when it is
    /// not JSON.
    ///
    /// # Panics
    ///
    /// If the socket cannot be reached or the exchange fails.
    pub async fn request(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        request(self.product, &self.socket, method, path, token, body).await
    }

    async fn wait_until_ready(&self) {
        let deadline = Instant::now() + READY_TIMEOUT;
        while Instant::now() < deadline {
            // Any answer will do, a `401` included: it is the listener that
            // has to be up, not a session.
            if send(self.product, &self.socket, Method::GET, "/ping", None, None)
                .await
                .is_ok()
            {
                return;
            }
            tokio::time::sleep(READY_POLL).await;
        }
        panic!(
            "{} did not answer on {} within {READY_TIMEOUT:?}; set {LOG_VAR}=1 to see its output",
            self.product.display_name,
            self.socket.display()
        );
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        shutdown(&mut self.child);
        let _ = std::fs::remove_dir_all(&self.home.root);
    }
}

/// `method /v1{path}` on the daemon of `product` at `socket`: what
/// [`TestDaemon::request`] sends, for a test that holds only the socket.
///
/// # Panics
///
/// If the socket cannot be reached or the exchange fails.
pub async fn request(
    product: &ProductSpec,
    socket: &Path,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Option<&serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let (status, bytes) = send(product, socket, method, path, token, body)
        .await
        .unwrap_or_else(|e| panic!("{path}: {e}"));
    let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, body)
}

/// Where a daemon of `product` in `home` discovers installed backends.
#[must_use]
pub fn backends_dir(product: &ProductSpec, home: &Home) -> PathBuf {
    home.data.join(product.slug).join("backends")
}

/// One exchange on `socket`.
async fn send(
    product: &ProductSpec,
    socket: &Path,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Option<&serde_json::Value>,
) -> Result<(StatusCode, Bytes), String> {
    let stream = UnixStream::connect(socket)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let (mut sender, conn) = handshake::<_, Full<Bytes>>(hyper_util::rt::TokioIo::new(stream))
        .await
        .map_err(|e| format!("handshake: {e}"))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let host = product.http_host();
    let mut request = Request::builder()
        .method(method)
        .uri(format!("http://{host}/v1{path}"))
        .header("host", &host);
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let bytes = match body {
        Some(body) => {
            request = request.header("content-type", "application/json");
            Bytes::from(serde_json::to_vec(body).map_err(|e| format!("encode: {e}"))?)
        }
        None => Bytes::new(),
    };
    let request = request
        .body(Full::new(bytes))
        .map_err(|e| format!("build: {e}"))?;

    let response = sender
        .send_request(request)
        .await
        .map_err(|e| format!("send: {e}"))?;
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("read: {e}"))?
        .to_bytes();
    Ok((status, bytes))
}

/// Stop a spawned daemon the way anything else stops one: `SIGINT`, then wait
/// for it to exit on its own, and `SIGKILL` it only after ten seconds.
///
/// [`Child::kill`] alone sends `SIGKILL`, which no process can handle, and
/// that costs more than an unclean exit. Under `cargo llvm-cov` the daemon is
/// an instrumented binary that writes its profile from an `atexit` hook, which
/// a killed process never runs, so everything the test exercised reads as
/// uncovered. A killed daemon also skips its own shutdown, which is what stops
/// its subprocess backends' `systemd --user` units. `SIGINT` runs that path,
/// so the tests exercise the shutdown the daemon is written for.
pub fn shutdown(child: &mut Child) {
    // Already gone? A test that stops its daemon mid-run reaches this having
    // reaped it, and the pid may since have been reused. Never signal that.
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    let Ok(pid) = i32::try_from(child.id()) else {
        let _ = child.kill();
        let _ = child.wait();
        return;
    };
    // SAFETY: `pid` is our own child, and nothing has reaped it (the `wait`
    // calls are below), so the pid cannot have been reused.
    let _ = unsafe { libc::kill(pid, libc::SIGINT) };

    let deadline = Instant::now() + SHUTDOWN_GRACE;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) => std::thread::sleep(SHUTDOWN_POLL),
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;
    use super_engine_protocol::test_product::TEST;

    /// The home and the switches every test daemon starts with.
    #[test]
    fn a_test_daemon_starts_isolated_and_quiet() {
        let builder = TestDaemon::build(&TEST, "/bin/true", "unit");
        let home = builder.home().clone();
        let value = |key: &str| {
            builder
                .env
                .get(OsStr::new(key))
                .cloned()
                .flatten()
                .map(|v| v.to_string_lossy().into_owned())
        };
        assert_eq!(value("SUPER_TEST_KEYRING_MOCK").as_deref(), Some("1"));
        assert_eq!(value("SUPER_TEST_AUTO_APPROVE").as_deref(), Some("1"));
        assert_eq!(value("SUPER_TEST_MUTE_CUES").as_deref(), Some("1"));
        assert_eq!(
            value("XDG_CACHE_HOME").as_deref(),
            home.cache.to_str(),
            "a shared registry cache is one test daemon overwriting another's"
        );
        assert_eq!(
            value("SUPER_TEST_HTTP_SOCKET").as_deref(),
            builder.socket().to_str()
        );
        assert!(home.data.is_dir() && home.config.is_dir() && home.cache.is_dir());
        assert_eq!(
            backends_dir(&TEST, &home),
            home.data.join("super-test").join("backends")
        );

        let builder = builder.without("SUPER_TEST_AUTO_APPROVE");
        assert_eq!(value_of(&builder, "SUPER_TEST_AUTO_APPROVE"), None);
        let _ = std::fs::remove_dir_all(home.root());
    }

    fn value_of(builder: &Builder, key: &str) -> Option<OsString> {
        builder.env.get(OsStr::new(key)).cloned().flatten()
    }

    /// A test of the default socket path gets the daemon's own default, under
    /// the home, and no override.
    #[test]
    fn the_default_socket_is_the_daemons_own() {
        let builder = TestDaemon::build(&TEST, "/bin/true", "unit").default_socket();
        let root = builder.home().root().to_owned();
        assert_eq!(value_of(&builder, "SUPER_TEST_HTTP_SOCKET"), None);
        assert_eq!(
            value_of(&builder, "XDG_RUNTIME_DIR"),
            Some(root.join("runtime").into_os_string())
        );
        assert_eq!(
            builder.socket(),
            root.join("runtime/test/super-test-http.sock")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// A socket put somewhere else is where the daemon is told to bind.
    #[test]
    fn a_socket_put_elsewhere_is_the_one_the_daemon_binds() {
        let builder = TestDaemon::build(&TEST, "/bin/true", "unit").socket_at("/tmp/x.sock");
        assert_eq!(builder.socket(), Path::new("/tmp/x.sock"));
        assert_eq!(
            value_of(&builder, "SUPER_TEST_HTTP_SOCKET"),
            Some(OsString::from("/tmp/x.sock"))
        );
        let _ = std::fs::remove_dir_all(builder.home().root());
    }

    /// Two daemons from one test binary never share a home.
    #[test]
    fn each_daemon_gets_a_home_of_its_own() {
        let a = TestDaemon::build(&TEST, "/bin/true", "unit");
        let b = TestDaemon::build(&TEST, "/bin/true", "unit");
        assert_ne!(a.home().root(), b.home().root());
        let _ = std::fs::remove_dir_all(a.home().root());
        let _ = std::fs::remove_dir_all(b.home().root());
    }

    /// A child that never opens its socket gets no answer, and `stop` ends
    /// it rather than leaving it running.
    #[tokio::test]
    async fn stop_ends_a_daemon_that_never_answered() {
        let mut command = Command::new("sleep");
        command.arg("30");
        let child = command.spawn().unwrap();
        let home = Home::new(&TEST, "unit");
        let mut daemon = TestDaemon {
            child,
            product: &TEST,
            socket: home.root.join("http.sock"),
            home,
        };
        assert!(
            send(&TEST, daemon.socket(), Method::GET, "/ping", None, None)
                .await
                .is_err()
        );
        daemon.stop();
        assert!(matches!(daemon.child().try_wait(), Ok(Some(_))));
    }
}
