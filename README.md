# Super Engine

The code shared by daemons that serve models from out-of-tree backends, and
by their clients, so a fix lands once instead of in every product.

| Crate | What it holds | Used by |
|---|---|---|
| `super-engine-spec` | The backend contract: `backend.toml`, `registry.toml` and `index.json`, their JSON schemas, and release verification. Generic over the product, which supplies its contract generations and its own manifest fields. | Daemons, indexers, settings apps |
| `super-engine-forge` | Release discovery and asset download from git forges. | Daemons, indexers, installers |
| `super-engine-protocol` | What a daemon and its clients agree on: the names a product goes by (`ProductSpec`), its directories and socket, the scopes and event topics, and the small wire types every client reads, such as load progress and GPU info. Also the audio analyzer behind the spectrum the applets draw. | Daemons and every client |
| `super-engine-client` | A daemon client: the HTTP transport over the Unix socket, session tokens in the keyring, and the self-healing `/events` subscription. | Settings apps, CLIs, applets |
| `super-engine-daemon` | What a daemon runs beside its own endpoints. Auth: session tokens, the consent dialog, the guards every route sits behind, the keyring and per-client rate limits. The Unix socket and TCP listeners, the event bus and `/events`, and self-update. Backends: the registry client, install pipeline and the logic behind the registry endpoints, discovery, downloads and their progress, and the WASM and subprocess runtimes. Also config loading, devices, language resolution, audio cues, the load gate and the shutdown signal. | Daemons |
| `super-engine-indexer` | Builds a product's `index.json` from its `registry.toml` and the backends' releases, and refuses what the contract does not allow to be published. | Each product's indexer |
| `super-engine-installer` | The installer and self-updater: resolve a release, stage it, install it with privilege escalation, and uninstall it. | Each product's installer |
| `super-engine-test-daemon` | Starts a product's daemon for an integration test, in a home of its own with the test switches set, and sends it requests. | Each product's integration tests |

Each product keeps what is its own: its `ProductSpec`, its contract
generations and manifest fields, its endpoints, and its request and response
types. Nothing here names a product.

## Shared CI

Each product runs the same CI jobs from here, pinned at the same rev as its
crates. A product's own workflow keeps its triggers, permissions and
concurrency, and passes its names:

1. `.github/workflows/build-index.yml` builds the registry index and
   publishes it to the product's gh-pages branch.
2. `.github/workflows/registry-index-pr.yml` builds the same index for a pull
   request and shows it without publishing it.
3. `.github/actions/install-e2e` installs the product's published release for
   real, checks the installed files, then uninstalls it. The script it runs,
   `test-install-e2e.sh`, lives next to it.

In a product, `just pin-engine <rev>` moves the crates and these jobs to a new
rev together.

## Checks

Run every check through `just`:

```sh
just ci          # format, clippy, tests, doctests
just check       # clippy only
just test
just fmt-check
```

## License

GPL-3.0-only. See [LICENSE](LICENSE).
