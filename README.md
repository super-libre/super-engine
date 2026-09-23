# Super Engine

The code shared by daemons that serve models from out-of-tree backends, and
by their clients, so a fix lands once instead of in every product.

| Crate | What it holds | Used by |
|---|---|---|
| `super-engine-spec` | The backend contract: `backend.toml`, `registry.toml` and `index.json`, their JSON schemas, and release verification. Generic over the product, which supplies its contract generations and its own manifest fields. | Daemons, indexers, settings apps |
| `super-engine-forge` | Release discovery and asset download from git forges. | Daemons, indexers, installers |
| `super-engine-protocol` | What a daemon and its clients agree on: the names a product goes by (`ProductSpec`), its directories and socket, the scopes and event topics, and the small wire types every client reads. | Daemons and every client |
| `super-engine-client` | A daemon client: the HTTP transport over the Unix socket, session tokens in the keyring, and the self-healing `/events` subscription. | Settings apps, CLIs, applets |
| `super-engine-daemon` | What a daemon runs beside its own endpoints: session tokens and the consent dialog, the guards every route sits behind, the keyring, per-client rate limits, and the Unix socket and TCP listeners. | Daemons |

Each product keeps what is its own: its `ProductSpec`, its contract
generations and manifest fields, its endpoints, and its request and response
types. Nothing here names a product.

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
