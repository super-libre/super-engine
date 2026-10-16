// SPDX-License-Identifier: GPL-3.0-only
//! A backend's lifecycle — start, load — driven against a backend served
//! in-process, which stands in for the sandbox and can be killed.
//!
//! Everything but the sandbox is the real path: the claim, the socket and
//! cache directories, the requests over the Unix socket, the status polls.

use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};

use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use super_engine_protocol::test_product::TEST;
use tokio::net::UnixListener;

use super::*;

/// What a test's stand-in backend was asked, across every time it was
/// started. Cloned into each server it runs, so a test reads what all of them
/// saw.
#[derive(Clone, Default)]
struct Fake(Arc<Seen>);

#[derive(Default)]
struct Seen {
    /// How many times the backend has been started.
    starts: AtomicUsize,
    /// Each `POST`, in order: its path, its body, and which start it reached.
    posts: parking_lot::Mutex<Vec<Post>>,
    /// The server of the latest start, while it runs.
    running: parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

#[derive(Debug, Clone, PartialEq)]
struct Post {
    path: String,
    body: serde_json::Value,
    /// 1 for the first start, 2 for the one after a restart.
    start: usize,
}

/// One running backend's own state, which a restart begins afresh.
#[derive(Clone, Copy)]
enum State {
    Starting,
    Ready,
}

impl Fake {
    fn posts(&self) -> Vec<Post> {
        self.0.posts.lock().clone()
    }

    fn starts(&self) -> usize {
        self.0.starts.load(Ordering::SeqCst)
    }

    /// Answer one request the way a backend would.
    fn answer(
        &self,
        start: usize,
        state: &parking_lot::Mutex<State>,
        method: &hyper::Method,
        path: &str,
        body: &[u8],
    ) -> (u16, serde_json::Value) {
        if method == hyper::Method::POST {
            self.0.posts.lock().push(Post {
                path: path.to_string(),
                body: serde_json::from_slice(body).unwrap_or_default(),
                start,
            });
        }
        let mut state = state.lock();
        match (path, *state) {
            ("/v1/ping", _) => (200, serde_json::json!({ "status": "success" })),
            ("/v1/load", State::Starting) => {
                *state = State::Ready;
                (202, serde_json::json!({ "status": "success" }))
            }
            ("/v1/load", State::Ready) => (409, error("already_loading")),
            ("/v1/status", State::Starting) => (200, status("starting")),
            ("/v1/status", State::Ready) => (
                200,
                serde_json::json!({ "status": "success", "state": "ready", "device": "cpu" }),
            ),
            _ => (404, error("not_found")),
        }
    }

    /// Serve one start of the backend on `socket` until it is killed.
    fn serve(&self, socket: &Path) -> Result<tokio::task::JoinHandle<()>> {
        let start = self.0.starts.fetch_add(1, Ordering::SeqCst) + 1;
        // What the platform spawners do too: a socket left by an earlier start
        // would refuse the bind.
        let _ = std::fs::remove_file(socket);
        let listener = UnixListener::bind(socket)?;
        let state = Arc::new(parking_lot::Mutex::new(State::Starting));
        let fake = self.clone();
        Ok(tokio::spawn(async move {
            // Owned here, so the connections go when the server does.
            let mut connections = tokio::task::JoinSet::new();
            while let Ok((stream, _)) = listener.accept().await {
                let fake = fake.clone();
                let state = Arc::clone(&state);
                let service = service_fn(move |req: Request<Incoming>| {
                    let fake = fake.clone();
                    let state = Arc::clone(&state);
                    async move {
                        let method = req.method().clone();
                        let path = req.uri().path().to_string();
                        let body = req
                            .into_body()
                            .collect()
                            .await
                            .map(http_body_util::Collected::to_bytes)
                            .unwrap_or_default();
                        let (status, json) = fake.answer(start, &state, &method, &path, &body);
                        let response = Response::builder()
                            .status(status)
                            .header("content-type", "application/json")
                            .body(Full::new(Bytes::from(json.to_string())))
                            .expect("a response from parts that are valid");
                        Ok::<_, Infallible>(response)
                    }
                });
                connections.spawn(async move {
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        }))
    }

    /// Kill the running backend, the way a driver fault would: it stops
    /// answering, and nothing is left listening on its socket.
    async fn kill(&self, socket: &Path) {
        let running = self.0.running.lock().take();
        if let Some(server) = running {
            server.abort();
            let _ = server.await;
        }
        let _ = std::fs::remove_file(socket);
    }
}

fn status(state: &str) -> serde_json::Value {
    serde_json::json!({ "status": "success", "state": state })
}

fn error(message: &str) -> serde_json::Value {
    serde_json::json!({ "status": "error", "message": message })
}

impl Spawn for Fake {
    fn spawn<'a>(&'a self, sandbox: &'a Sandbox<'a>) -> BoxFuture<'a, Result<Box<dyn Supervise>>> {
        Box::pin(async move {
            let server = self.serve(sandbox.socket)?;
            *self.0.running.lock() = Some(server);
            let supervisor: Box<dyn Supervise> = Box::new(FakeSupervisor {
                label: sandbox.instance.to_string(),
                fake: self.clone(),
                socket: sandbox.socket.to_path_buf(),
            });
            Ok(supervisor)
        })
    }
}

/// The handle to one start of a [`Fake`].
struct FakeSupervisor {
    label: String,
    fake: Fake,
    socket: PathBuf,
}

impl Supervise for FakeSupervisor {
    fn label(&self) -> &str {
        &self.label
    }

    fn logs(&self) -> String {
        "the stand-in backend writes no output".to_string()
    }

    fn stop(&mut self) -> BoxFuture<'_, ()> {
        Box::pin(self.fake.kill(&self.socket))
    }
}

/// A backend directory for one test, with the binary `start` checks for, and
/// the cache directory `start` makes for it removed again at the end.
struct BackendDir {
    /// Holds the directory, which goes when it drops.
    _root: tempfile::TempDir,
    path: PathBuf,
}

impl BackendDir {
    /// Named after the test, and this process, so that tests running at once
    /// — here or in another checkout — never hold the same instance.
    fn new(test: &str) -> Self {
        let root = tempfile::tempdir().expect("a temp dir");
        let path = root
            .path()
            .join(format!("app.super-test.{test}-{}", std::process::id()));
        std::fs::create_dir_all(&path).expect("the backend dir");
        std::fs::write(path.join(ENTRYPOINT), "").expect("the backend binary");
        Self { _root: root, path }
    }

    fn start(&self) -> Start<'_> {
        Start {
            backend_dir: &self.path,
            entrypoint: ENTRYPOINT,
            model: MODEL,
            provider: Some("local_fake"),
            devices: &[Device::Cpu],
            device_pref: "cpu",
            context_headers: Vec::new(),
        }
    }
}

impl Drop for BackendDir {
    fn drop(&mut self) {
        if let Ok(cache) = backend_cache_dir(&TEST, &self.path) {
            let _ = std::fs::remove_dir_all(cache);
        }
    }
}

const ENTRYPOINT: &str = "fake-backend";
const MODEL: &str = "fake-model";

/// The body every `POST` names the model with.
fn model_body() -> serde_json::Value {
    load_body(MODEL, Some("local_fake"), "cpu")
}

/// Start and load is what [`SubprocessBackend::spawn`] does in one call, and
/// the load names the model the backend was started for.
#[tokio::test]
async fn a_started_backend_loads_the_model_it_was_started_for() {
    let dir = BackendDir::new("start-then-load");
    let fake = Fake::default();
    let mut backend = SubprocessBackend::start_with(&TEST, dir.start(), Arc::new(fake.clone()))
        .await
        .expect("the backend starts");
    assert!(
        fake.posts().is_empty(),
        "a start must not load anything: {:?}",
        fake.posts()
    );

    backend.load(None).await.expect("the backend loads");
    assert_eq!(backend.device(), "cpu");
    assert_eq!(
        fake.posts(),
        [Post {
            path: "/v1/load".into(),
            body: model_body(),
            start: 1
        }]
    );
    backend.shutdown().await;
}

/// A started backend holds its instance exactly as a loaded one does: the
/// product may still be downloading, and a second start would take the
/// socket out from under it.
#[tokio::test]
async fn a_started_backend_holds_its_instance() {
    let dir = BackendDir::new("start-holds");
    let fake = Fake::default();
    let mut first = SubprocessBackend::start_with(&TEST, dir.start(), Arc::new(fake.clone()))
        .await
        .expect("the backend starts");
    let Err(second) =
        SubprocessBackend::start_with(&TEST, dir.start(), Arc::new(fake.clone())).await
    else {
        panic!("a second start of a started instance must be refused");
    };
    assert!(
        second.to_string().contains("already loading or loaded"),
        "{second:#}"
    );
    assert_eq!(
        fake.starts(),
        1,
        "the refused start must not spawn anything"
    );
    first.shutdown().await;
}
