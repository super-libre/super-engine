// SPDX-License-Identifier: GPL-3.0-only
//! Installed backends, as a daemon sees them.
//!
//! [`discover`] scans the backends directory into [`DiscoveredBackend`]s,
//! each carrying the [`ModelDefinition`]s it serves. [`validate_runtime`] is
//! the runtime policy a daemon holds a backend's `backend.toml` to at
//! discovery, on top of what `Manifest::parse` already enforces: the checks
//! only the daemon cares about.

mod discovery;
mod model;

pub use discovery::{
    DiscoveredBackend, default_backends_dir, dir_name, discover, find_model, installed_version,
    list_models,
};
pub use model::ModelDefinition;

use anyhow::Result;
use super_engine_spec::manifest::{Kind, Manifest};
use super_engine_spec::product::Product;

/// Path segments that name an operation rather than a resource, and so cannot
/// also name one.
///
/// Every collection in the API is addressed as `{noun}/list` for the whole set
/// and `{noun}/{name}` for one member. That is a good shape — it never mistakes
/// a member for the collection, and it reads the same at every level — but it
/// puts `list` and a member name in the same path segment, and a static segment
/// wins the route. A backend declaring an option called `list` would therefore
/// have it appear in the listing and be unreachable: no read, no write, no
/// clear, and nothing anywhere saying why.
///
/// Refusing the name at discovery is what makes the shape safe. The alternative
/// — percent-encoding, or a `?name=` query — costs every client something to
/// protect a name nobody wants.
const RESERVED_SEGMENTS: &[&str] = &["list"];

/// Reject an option or secret name that collides with a sibling route.
fn check_addressable_name(kind: &str, name: &str) -> Result<()> {
    if RESERVED_SEGMENTS.contains(&name) {
        anyhow::bail!(
            "{kind} `{name}` cannot be named that: `{name}` addresses the whole \
             collection at /backend/{{backend_id}}/{kind}/{name}, so a {kind} with \
             that name would be listed and then unreachable. Rename it."
        );
    }
    Ok(())
}

/// Validate cross-field invariants the daemon enforces at discovery. A
/// product with invariants of its own checks them after this.
///
/// # Errors
/// Returns an error if a subprocess backend declares the wasm-only
/// `websocket` capability or a non-empty `allowed_hosts` (the transport
/// provides no network), if an option or secret is named after a reserved path
/// segment (see [`RESERVED_SEGMENTS`]), if a model's `primary_language` is
/// absent from its `supported_languages`, if a non-multilingual model's
/// `supported_languages` is not exactly `[primary_language]`, or if a model
/// sets `realtime` without the `websocket` capability.
pub fn validate_runtime<P: Product>(m: &Manifest<P>) -> Result<()> {
    if m.backend.kind == Kind::Subprocess && m.capabilities.websocket {
        anyhow::bail!(
            "[capabilities].websocket is wasm-only; subprocess backends cannot declare it"
        );
    }
    if m.backend.kind == Kind::Subprocess && !m.network.allowed_hosts.is_empty() {
        anyhow::bail!(
            "[network].allowed_hosts must be empty for subprocess backends; the transport provides no network"
        );
    }
    for opt in &m.options {
        check_addressable_name("option", &opt.name)?;
    }
    for secret in &m.secrets {
        check_addressable_name("secret", &secret.name)?;
    }
    for model in &m.models {
        if !model.supported_languages.contains(&model.primary_language) {
            anyhow::bail!(
                "model `{}` primary_language `{}` is not in supported_languages",
                model.name,
                model.primary_language
            );
        }
        if !model.multilingual
            && model.supported_languages.as_slice() != [model.primary_language.clone()]
        {
            anyhow::bail!(
                "model `{}` has multilingual = false but supported_languages is not exactly [primary_language]",
                model.name
            );
        }
        if model.realtime && !m.capabilities.websocket {
            anyhow::bail!(
                "model `{}` has realtime = true but capabilities.websocket is not set",
                model.name
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_runtime;
    use super_engine_spec::test_product::TestProduct;

    type Manifest = super_engine_spec::manifest::Manifest<TestProduct>;

    #[test]
    fn subprocess_with_websocket_capability_is_rejected() {
        let toml_src = r#"
[backend]
source = "github.com/example/whisper"
name = "Whisper"
version = "0.1.0"
kind = "subprocess"
entrypoint = "example-backend-whisper"
contract = "v1"
description = "Test backend."

[capabilities]
websocket = true
"#;
        let m = Manifest::parse(toml_src).expect("parse");
        let err = validate_runtime(&m).expect_err("subprocess + websocket must fail");
        assert!(err.to_string().contains("wasm-only"), "got: {err}");
    }

    #[test]
    fn subprocess_with_allowed_hosts_is_rejected() {
        let toml_src = r#"
[backend]
source = "github.com/example/whisper"
name = "Whisper"
version = "0.1.0"
kind = "subprocess"
entrypoint = "whisper-backend"
contract = "v1"
description = "Test backend."

[network]
allowed_hosts = ["api.example.com"]
"#;
        let m = Manifest::parse(toml_src).expect("parse");
        let err = validate_runtime(&m).expect_err("subprocess + allowed_hosts must fail");
        assert!(err.to_string().contains("allowed_hosts"), "got: {err}");
    }

    #[test]
    fn wasm_with_allowed_hosts_is_accepted() {
        let toml_src = r#"
[backend]
source = "github.com/example/openai"
name = "OpenAI"
version = "0.1.0"
kind = "wasm"
entrypoint = "openai.wasm"
contract = "v1"
description = "Test backend."

[network]
allowed_hosts = ["api.openai.com"]
"#;
        let m = Manifest::parse(toml_src).expect("parse");
        validate_runtime(&m).expect("wasm + allowed_hosts is permitted");
    }

    #[test]
    fn primary_language_not_in_supported_is_rejected() {
        let toml_src = r#"
[backend]
source = "github.com/example/whisper"
name = "Whisper"
version = "0.1.0"
kind = "subprocess"
entrypoint = "whisper-backend"
contract = "v1"
description = "Test backend."

[[models]]
name = "whisper-tiny"
multilingual = true
primary_language = "en"
supported_languages = ["es", "fr"]
supported_devices = ["cpu"]
"#;
        let m = Manifest::parse(toml_src).expect("parse");
        let err = validate_runtime(&m)
            .expect_err("primary_language outside supported_languages must fail");
        assert!(err.to_string().contains("primary_language"), "got: {err}");
    }

    #[test]
    fn multilingual_false_with_extra_languages_is_rejected() {
        let toml_src = r#"
[backend]
source = "github.com/example/whisper"
name = "Whisper"
version = "0.1.0"
kind = "subprocess"
entrypoint = "whisper-backend"
contract = "v1"
description = "Test backend."

[[models]]
name = "whisper-en"
multilingual = false
primary_language = "en"
supported_languages = ["en", "es"]
supported_devices = ["cpu"]
"#;
        let m = Manifest::parse(toml_src).expect("parse");
        let err =
            validate_runtime(&m).expect_err("multilingual = false with extra languages must fail");
        assert!(err.to_string().contains("multilingual"), "got: {err}");
    }

    #[test]
    fn multilingual_false_with_exact_primary_language_is_accepted() {
        let toml_src = r#"
[backend]
source = "github.com/example/whisper"
name = "Whisper"
version = "0.1.0"
kind = "subprocess"
entrypoint = "whisper-backend"
contract = "v1"
description = "Test backend."

[[models]]
name = "whisper-en"
multilingual = false
primary_language = "en"
supported_languages = ["en"]
supported_devices = ["cpu"]
"#;
        let m = Manifest::parse(toml_src).expect("parse");
        validate_runtime(&m)
            .expect("multilingual = false with exactly [primary_language] is valid");
    }

    #[test]
    fn realtime_model_without_websocket_capability_is_rejected() {
        let toml_src = r#"
[backend]
source = "github.com/example/mistral"
name = "Mistral"
version = "0.2.0"
kind = "wasm"
entrypoint = "mistral.wasm"
contract = "v1"
description = "Test backend."

[[models]]
name = "voxtral-mini-transcribe-realtime-2602"
multilingual = true
primary_language = "en"
supported_languages = ["en"]
supported_devices = ["none"]
realtime = true
"#;
        let m = Manifest::parse(toml_src).expect("parse");
        let err = validate_runtime(&m)
            .expect_err("realtime model without websocket capability must fail");
        assert!(
            err.to_string().contains("capabilities.websocket"),
            "got: {err}"
        );
    }

    /// An option named after the collection's own route segment is refused at
    /// discovery.
    ///
    /// The regression this exists for is silent: `list` and `{name}` share a
    /// path segment, and the static route wins, so such an option appeared in
    /// the listing and could not be read, written or cleared — with nothing
    /// anywhere saying why. The name is what has to give, and it gives here,
    /// where a backend author sees the reason.
    #[test]
    fn an_option_named_after_a_reserved_segment_is_refused() {
        let toml_src = r#"
[backend]
source = "github.com/example/openai"
name = "OpenAI"
version = "0.1.0"
kind = "wasm"
entrypoint = "openai.wasm"
contract = "v1"
description = "Test backend."

[[options]]
name = "list"
description = "Shadowed by the collection route."
"#;
        let manifest = Manifest::parse(toml_src).expect("parse");
        let err = validate_runtime(&manifest).expect_err("a reserved option name is refused");
        let text = err.to_string();
        assert!(text.contains("option `list`"), "names the offender: {text}");
        assert!(
            text.contains("unreachable"),
            "says what would happen, not just that it is refused: {text}"
        );
    }

    /// The same rule for secrets, which share the shape and the hazard.
    #[test]
    fn a_secret_named_after_a_reserved_segment_is_refused() {
        let toml_src = r#"
[backend]
source = "github.com/example/openai"
name = "OpenAI"
version = "0.1.0"
kind = "wasm"
entrypoint = "openai.wasm"
contract = "v1"
description = "Test backend."

[[secrets]]
name = "list"
description = "Shadowed by the collection route."
required = false
"#;
        let manifest = Manifest::parse(toml_src).expect("parse");
        let err = validate_runtime(&manifest).expect_err("a reserved secret name is refused");
        assert!(
            err.to_string().contains("secret `list`"),
            "names the offender: {err}"
        );
    }

    /// And a name that merely contains the reserved word is fine — the check is
    /// on the whole segment, since that is what routing matches.
    #[test]
    fn a_name_containing_a_reserved_word_is_fine() {
        let toml_src = r#"
[backend]
source = "github.com/example/openai"
name = "OpenAI"
version = "0.1.0"
kind = "wasm"
entrypoint = "openai.wasm"
contract = "v1"
description = "Test backend."

[[options]]
name = "allow_list"
description = "Not a collision."
"#;
        let manifest = Manifest::parse(toml_src).expect("parse");
        validate_runtime(&manifest).expect("allow_list is addressable");
    }
}
