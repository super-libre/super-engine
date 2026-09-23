# Super Engine

The code [Super STT](https://github.com/jorge-menjivar/super-stt) and Super TTS
share, so a fix lands once instead of in both.

| Crate | What it holds | Used by |
|---|---|---|
| `super-engine-spec` | The backend contract: `backend.toml`, `registry.toml` and `index.json`, their JSON schemas, and release verification. Generic over the product, which supplies its contract generations and its own manifest fields. | Daemons, indexers, settings apps |
| `super-engine-forge` | Release discovery and asset download from git forges. | Daemons, indexers, installers |
| `super-engine-protocol` | What a daemon and its clients agree on: each product's names (`ProductSpec`), its directories and socket, the scopes and event topics, and the small wire types every client reads. | Daemons and every client |
| `super-engine-client` | A daemon client: the HTTP transport over the Unix socket, session tokens in the keyring, and the self-healing `/events` subscription. | Settings apps, CLIs, the COSMIC applet |
| `super-engine-daemon` | What a daemon runs beside its own endpoints: session tokens and the consent dialog, the guards every route sits behind, the keyring, per-client rate limits, and the Unix socket and TCP listeners. | Daemons |

Each product keeps what is its own: its contract generations and manifest
fields, its endpoints (transcribe, speak, voices), and its request and
response types.

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
