// SPDX-License-Identifier: GPL-3.0-only
//! Registry policy for a backend's `backend.toml` at a tag: what a release
//! must meet to be published, on top of what `Manifest::parse` already
//! enforces. The manifest types and parser are `super_engine_spec`'s.

use semver::Version;
use thiserror::Error;

pub use super_engine_spec::manifest::ManifestError as ParseError;
use super_engine_spec::manifest::{Kind, Manifest, Opt, OptionType};
use super_engine_spec::product::Product;

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error(transparent)]
    Parse(#[from] ParseError),
    #[error("`backend.version = {0:?}` does not match tag version `{1}`")]
    VersionMismatch(String, Version),
    #[error("`backend.source = {0:?}` does not match registry entry repo `{1}`")]
    SourceMismatch(String, String),
    /// The release manifest's `[backend].id` does not equal the `id` declared
    /// by the `registry.toml` entry that points at this release.
    #[error("manifest declares `id = {0:?}` but the registry entry declares {1:?}")]
    IdMismatch(String, String),
    #[error("`backend.kind = \"wasm\"` requires `[assets.wasm]` but it is missing")]
    MissingWasmAsset,
    #[error("`backend.kind = \"subprocess\"` requires `[[assets.subprocess]]` but list is empty")]
    MissingSubprocessAssets,
    #[error("missing license; declare `[backend].license` (a recognized SPDX id or \"other\")")]
    MissingLicense,
    #[error(
        "license `{0}` is not a recognized open-source license; use a current \
         OSI-approved or FSF Free/Libre SPDX identifier (e.g. Apache-2.0, MIT, \
         GPL-3.0-only) or \"other\""
    )]
    LicenseNotAllowed(String),
    #[error(
        "option `base_url` must not declare a `default`: its value authorizes \
         egress the sandbox would otherwise refuse, so it has to come from the \
         user. Carry the endpoint in the component and leave the option as an \
         override."
    )]
    BaseUrlDefault,
    /// An option's `default` is not one of the values its `choices` allow.
    #[error(
        "option `{0}` declares `default = {1:?}` but its `choices` do not offer \
         it: the value a user never changes would be one the option rejects"
    )]
    DefaultNotAChoice(String, String),
    /// A `bool` option declared choices. It is rendered as a switch, and a
    /// switch has exactly the two values the type already names.
    #[error(
        "option `{0}` is a `bool` and must not declare `choices`: a boolean is \
         rendered as a switch, whose values are already true and false"
    )]
    BoolWithChoices(String),
    /// The same value appears twice in one option's `choices`.
    #[error("option `{0}` lists the choice {1:?} more than once")]
    DuplicateChoice(String, String),
    /// A `default` or a `choices` entry is not of the type the option
    /// declares. The daemon stores option values as text and checks them
    /// against that type on the way in, so a manifest naming a value of
    /// another type names one it would then refuse.
    #[error(
        "option `{0}` declares `type = \"{2}\"` but offers the value {1:?}, \
         which is not one: the daemon would refuse the value its own manifest \
         names"
    )]
    ValueNotTheType(String, String, String),
    /// `min`, `max` or `step` on an option whose type has no ordering to
    /// bound. A range over strings is not a thing the manifest can mean.
    #[error(
        "option `{0}` declares a numeric range but `type = \"{1}\"`: only \
         `integer` and `float` options can be bounded"
    )]
    RangeOnNonNumeric(String, String),
    /// The bounds do not describe a usable range.
    #[error("option `{0}` declares an unusable range: {1}")]
    InvalidRange(String, String),
    /// An option named both a closed set and a range. A client renders one
    /// control, and these ask for two different ones.
    #[error(
        "option `{0}` declares both `choices` and a numeric range: a closed \
         set is already the values it accepts, and a client cannot render a \
         dropdown and a slider at once"
    )]
    ChoicesWithRange(String),
    /// The default the daemon injects when nobody sets one is outside the
    /// range the option itself declares.
    #[error(
        "option `{0}` declares `default = {1}` but its own range does not \
         reach it: the value a user never changes would be one the option \
         rejects"
    )]
    DefaultOutOfRange(String, String),
    /// A slider with nothing to rest on. Every other control can render
    /// "nothing set" — an empty field, an unpicked dropdown — but a slider
    /// always shows a position, and a position the backend did not choose is
    /// a value the user never set being shown to them as though they had.
    #[error(
        "option `{0}` declares `step`, which makes it a slider, but no \
         `default`: a slider always rests somewhere, so it has to rest on a \
         value the backend named"
    )]
    SliderWithoutDefault(String),
    /// An option's `default` cannot be delivered to the backend as a request
    /// header. Refused at publication because nobody installing the backend can
    /// work around it: the default is what they get for touching nothing.
    #[error("option `{0}` has a default that cannot be sent to the backend: {1}")]
    UndeliverableDefault(String, String),
}

/// Check a parsed manifest against the registry's publication rules.
///
/// `expected_version` is the release tag's version, `expected_source` the
/// registry entry's repo, and `expected_id` the `id` the entry declares, if
/// any.
///
/// # Errors
/// The first rule the manifest breaks.
pub fn validate<P: Product>(
    m: &Manifest<P>,
    expected_version: &Version,
    expected_source: &str,
    expected_id: Option<&str>,
) -> Result<(), ManifestError> {
    // Parse via the one shared version parser (v-prefix strip + semver) so the
    // manifest check can't drift from the daemon/app/resolve logic (Tier 1 #31).
    let v = super_engine_spec::version::parse_version(&m.backend.version).ok_or_else(|| {
        ManifestError::VersionMismatch(m.backend.version.clone(), expected_version.clone())
    })?;
    if &v != expected_version {
        return Err(ManifestError::VersionMismatch(
            m.backend.version.clone(),
            expected_version.clone(),
        ));
    }
    // The backend's `source` is its unique identity and must be controlled by
    // whoever controls the release `repo`: either it equals the repo (a
    // single-backend repo) or it is namespaced under it (a monorepo, where
    // several backends share one repo but each needs a distinct source). A
    // source pointing outside the repo is rejected as spoofing.
    let under_repo = m.backend.source.starts_with(&format!("{expected_source}/"));
    if m.backend.source != expected_source && !under_repo {
        return Err(ManifestError::SourceMismatch(
            m.backend.source.clone(),
            expected_source.into(),
        ));
    }
    // An entry that declares an `id` pins the release to it. This is the same
    // class of check as `SourceMismatch`: whoever controls the entry controls
    // which identity the release may claim, so a release cannot rename itself
    // into another backend's install directory.
    if let Some(want) = expected_id
        && m.backend.id.as_deref() != Some(want)
    {
        return Err(ManifestError::IdMismatch(
            m.backend.id.clone().unwrap_or_default(),
            want.to_string(),
        ));
    }
    match m.backend.kind {
        Kind::Wasm => {
            if m.assets.wasm.is_none() {
                return Err(ManifestError::MissingWasmAsset);
            }
        }
        Kind::Subprocess => {
            if m.assets.subprocess.is_empty() {
                return Err(ManifestError::MissingSubprocessAssets);
            }
        }
    }
    // Accel/cuda/rocm/vulkan cross-field validation (`cuda_major` required when
    // `accel` contains `cuda`, and so on) is enforced by `Manifest::parse`
    // itself, which every caller of `validate` has already run successfully —
    // repeating it here would be dead code that can never trigger.
    // A `base_url` value is user intent: the daemon authorizes the host it names
    // for egress with the SSRF guard relaxed. A manifest-supplied one is the
    // backend author's, so a release carrying it does not go in the registry.
    // The daemon is laxer on purpose — it drops the value and loads the backend
    // — because refusing to load punishes the user for the author's mistake;
    // refusing to publish stops it reaching users at all.
    if m.options
        .iter()
        .any(|o| o.name == super_engine_spec::manifest::BASE_URL_OPTION && o.default.is_some())
    {
        return Err(ManifestError::BaseUrlDefault);
    }
    // A closed set of values has to be internally consistent, and the settings
    // UI renders it as a dropdown that cannot express a contradiction: a
    // default outside the list, or a duplicate entry, would be a list the user
    // can neither choose from nor return to. Caught at publication because the
    // daemon reads a manifest it cannot fix.
    for o in &m.options {
        // A default is delivered exactly as a user-set value is, so it has to
        // survive the same journey: the daemon injects it as an
        // `x-<product>-option-*` header when the user has set nothing. A
        // default carrying a line break breaks the header for everyone who
        // installs the backend and never touches the setting — the failure no
        // user action could cause and none can undo.
        if let Some(default) = &o.default
            && let Err(e) = o.permits_shape(&default.to_string())
        {
            return Err(ManifestError::UndeliverableDefault(o.name.clone(), e));
        }
        // A declared type is a promise about every value the entry itself
        // names — the default the daemon injects when nobody sets one, and
        // each rung of a dropdown. Checked before the closed-set rules below,
        // and whether or not there is a closed set, because a `float` option
        // whose default is `brisk` is broken with or without `choices`.
        for value in o.default.iter().chain(o.choices.iter()) {
            let value = value.to_string();
            if !o.accepts_the_type(&value) {
                return Err(ManifestError::ValueNotTheType(
                    o.name.clone(),
                    value,
                    o.declared_type().to_string(),
                ));
            }
        }
        check_range(o)?;
        if o.choices.is_empty() {
            continue;
        }
        if o.r#type == Some(OptionType::Bool) {
            return Err(ManifestError::BoolWithChoices(o.name.clone()));
        }
        let mut seen: Vec<String> = Vec::with_capacity(o.choices.len());
        for choice in &o.choices {
            let choice = choice.to_string();
            if seen.contains(&choice) {
                return Err(ManifestError::DuplicateChoice(o.name.clone(), choice));
            }
            seen.push(choice);
        }
        if let Some(default) = &o.default
            && !o.is_a_choice(&default.to_string())
        {
            return Err(ManifestError::DefaultNotAChoice(
                o.name.clone(),
                default.to_string(),
            ));
        }
    }
    crate::license::check(m.backend.license.as_deref())?;
    Ok(())
}

/// The `min` / `max` / `step` rules for one option.
///
/// Checked at publication because the daemon reads a manifest it cannot fix:
/// a range it cannot satisfy would either refuse every value or be ignored,
/// and neither is something a user could diagnose from the settings sheet.
fn check_range(o: &Opt) -> Result<(), ManifestError> {
    let bounds = [o.min, o.max, o.step];
    if bounds.iter().all(Option::is_none) {
        return Ok(());
    }
    let numeric = matches!(o.declared_type(), OptionType::Integer | OptionType::Float);
    if !numeric {
        return Err(ManifestError::RangeOnNonNumeric(
            o.name.clone(),
            o.declared_type().to_string(),
        ));
    }
    if !o.choices.is_empty() {
        return Err(ManifestError::ChoicesWithRange(o.name.clone()));
    }
    let invalid = |why: &str| ManifestError::InvalidRange(o.name.clone(), why.to_string());
    for value in bounds.into_iter().flatten() {
        if !value.is_finite() {
            return Err(invalid("a bound must be a finite number"));
        }
        // An `integer` option whose slider notches are fractions is one whose
        // control cannot produce a value the option accepts.
        if o.declared_type() == OptionType::Integer && value.fract() != 0.0 {
            return Err(invalid(
                "an `integer` option's bounds must be whole numbers",
            ));
        }
    }
    if let (Some(low), Some(high)) = (o.min, o.max)
        && low > high
    {
        return Err(invalid("`min` is above `max`"));
    }
    if let Some(step) = o.step {
        if step <= 0.0 {
            return Err(invalid("`step` must be greater than zero"));
        }
        // `step` is what makes the option a slider, and a slider needs both
        // ends to have anything to slide between.
        let (Some(low), Some(high)) = (o.min, o.max) else {
            return Err(invalid("`step` needs both `min` and `max`"));
        };
        if step > high - low {
            return Err(invalid("`step` is larger than the range it divides"));
        }
        if o.default.is_none() {
            return Err(ManifestError::SliderWithoutDefault(o.name.clone()));
        }
    }
    if let Some(default) = &o.default
        && !o.is_in_range(&default.to_string())
    {
        return Err(ManifestError::DefaultOutOfRange(
            o.name.clone(),
            default.to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    type Manifest =
        super_engine_spec::manifest::Manifest<super_engine_spec::test_product::TestProduct>;

    const VALID: &str = r#"
        [backend]
        source = "github.com/x/y"
        name = "Y"
        version = "1.0.0"
        kind = "wasm"
        entrypoint = "y.wasm"
        contract = "v1"
        description = "Test backend."
        license = "Apache-2.0"

        [assets]
        wasm = "y.wasm"
    "#;

    fn with_id(id: &str) -> String {
        VALID.replace("[backend]", &format!("[backend]\n    id = \"{id}\""))
    }

    fn with_option(body: &str) -> String {
        format!("{VALID}\n[[options]]\n{body}\n")
    }

    fn validate_option(body: &str) -> Result<(), ManifestError> {
        let m = Manifest::parse(&with_option(body)).expect("parses");
        validate(&m, &Version::new(1, 0, 0), "github.com/x/y", None)
    }

    /// A closed set of values is only useful if it is coherent, and the
    /// registry is where an author finds out — the daemon reads a manifest it
    /// cannot fix, and the settings UI renders a dropdown that cannot express
    /// a default sitting outside its own list.
    #[test]
    fn a_choice_list_must_offer_its_own_default() {
        validate_option(
            r#"
            name = "styling"
            description = "The register."
            default = "formal"
            choices = ["casual", "formal"]
            "#,
        )
        .expect("a default on the list validates");

        let err = validate_option(
            r#"
            name = "styling"
            description = "The register."
            default = "brisk"
            choices = ["casual", "formal"]
            "#,
        )
        .expect_err("a default off the list is refused");
        assert!(
            matches!(err, ManifestError::DefaultNotAChoice(ref n, ref d) if n == "styling" && d == "brisk"),
            "got: {err}"
        );
    }

    #[test]
    fn a_float_option_takes_fractional_choices() {
        validate_option(
            r#"
            name = "temperature"
            description = "How freely the model samples."
            type = "float"
            choices = [0.7, 0.8, 0.9]
            "#,
        )
        .expect("a float option may offer fractional values");
    }

    /// The manifest may not name a value the daemon would then refuse to
    /// store. Caught at publication, where it can still be fixed.
    #[test]
    fn an_option_cannot_offer_a_value_of_another_type() {
        let err = validate_option(
            r#"
            name = "temperature"
            description = "How freely the model samples."
            type = "float"
            default = "brisk"
            "#,
        )
        .expect_err("a float option cannot default to a word");
        assert!(
            matches!(err, ManifestError::ValueNotTheType(ref n, ref v, ref t)
                if n == "temperature" && v == "brisk" && t == "float"),
            "got: {err}"
        );

        let err = validate_option(
            r#"
            name = "retries"
            description = "How many times to try again."
            type = "integer"
            choices = [1, 2, 2.5]
            "#,
        )
        .expect_err("an integer option cannot offer a fraction");
        assert!(
            matches!(err, ManifestError::ValueNotTheType(ref n, ref v, ref t)
                if n == "retries" && v == "2.5" && t == "integer"),
            "got: {err}"
        );
    }

    /// A whole number written into a float option is still a float. TOML
    /// spells it as an integer and the untagged enum binds it as one, so this
    /// is the check that the type rule reads the value and not the spelling.
    #[test]
    fn a_float_option_accepts_a_whole_number() {
        validate_option(
            r#"
            name = "gain"
            description = "Output gain."
            type = "float"
            default = 1
            "#,
        )
        .expect("1 is a float");
    }

    #[test]
    fn a_bounded_numeric_option_validates() {
        validate_option(
            r#"
            name = "temperature"
            description = "How freely the model samples."
            type = "float"
            default = 0.9
            min = 0.6
            max = 1.2
            step = 0.1
            "#,
        )
        .expect("a slider over a float range validates");

        validate_option(
            r#"
            name = "retries"
            description = "How many times to try again."
            type = "integer"
            default = 3
            min = 0
            max = 10
            step = 1
            "#,
        )
        .expect("and over an integer range");
    }

    /// A range over something with no ordering is not a thing the manifest can
    /// mean, and a client has no control to render for it.
    #[test]
    fn only_a_numeric_option_can_be_bounded() {
        let err = validate_option(
            r#"
            name = "styling"
            description = "The register."
            type = "string"
            min = 0.0
            max = 1.0
            "#,
        )
        .expect_err("a string has no range");
        assert!(
            matches!(err, ManifestError::RangeOnNonNumeric(ref n, ref t)
                if n == "styling" && t == "string"),
            "got: {err}"
        );
    }

    /// A client renders one control. A closed set and a range ask for two.
    #[test]
    fn an_option_cannot_be_both_a_dropdown_and_a_slider() {
        let err = validate_option(
            r#"
            name = "temperature"
            description = "How freely the model samples."
            type = "float"
            choices = [0.7, 0.9]
            min = 0.6
            max = 1.2
            step = 0.1
            "#,
        )
        .expect_err("a dropdown and a slider at once");
        assert!(
            matches!(err, ManifestError::ChoicesWithRange(ref n) if n == "temperature"),
            "got: {err}"
        );
    }

    #[test]
    fn a_range_has_to_be_one() {
        for (body, why) in [
            ("min = 1.2\nmax = 0.6\n", "reversed"),
            ("min = 0.0\nmax = 1.0\nstep = 0.0\n", "a zero step"),
            ("min = 0.0\nmax = 1.0\nstep = -0.1\n", "a negative step"),
            (
                "min = 0.0\nmax = 1.0\nstep = 2.0\n",
                "a step past the range",
            ),
            ("step = 0.1\n", "a step with no ends"),
            ("min = 0.0\nstep = 0.1\n", "a step with one end"),
        ] {
            let err = validate_option(&format!(
                "name = \"t\"\ndescription = \"T.\"\ntype = \"float\"\n{body}"
            ))
            .expect_err(why);
            assert!(
                matches!(err, ManifestError::InvalidRange(ref n, _) if n == "t"),
                "{why}: got {err}"
            );
        }
    }

    /// The bounds of an `integer` option have to be whole, or its slider
    /// produces values the option itself refuses.
    #[test]
    fn an_integer_range_is_whole() {
        let err = validate_option(
            r#"
            name = "retries"
            description = "How many times to try again."
            type = "integer"
            min = 0
            max = 10
            step = 0.5
            "#,
        )
        .expect_err("half a retry is not a retry");
        assert!(
            matches!(err, ManifestError::InvalidRange(ref n, _) if n == "retries"),
            "got: {err}"
        );
    }

    /// The value a user never changes must be one the option accepts.
    #[test]
    fn a_range_must_reach_its_own_default() {
        let err = validate_option(
            r#"
            name = "temperature"
            description = "How freely the model samples."
            type = "float"
            default = 2.0
            min = 0.6
            max = 1.2
            "#,
        )
        .expect_err("a default outside its own range is refused");
        assert!(
            matches!(err, ManifestError::DefaultOutOfRange(ref n, ref d)
                if n == "temperature" && d == "2.0"),
            "got: {err}"
        );
    }

    /// Every other control can render "nothing set". A slider cannot.
    #[test]
    fn a_slider_must_rest_on_a_declared_default() {
        let err = validate_option(
            r#"
            name = "temperature"
            description = "How freely the model samples."
            type = "float"
            min = 0.6
            max = 1.2
            step = 0.1
            "#,
        )
        .expect_err("a slider with nothing to rest on");
        assert!(
            matches!(err, ManifestError::SliderWithoutDefault(ref n) if n == "temperature"),
            "got: {err}"
        );

        // Bounds without a step are a validated field, not a slider, and a
        // field can perfectly well start empty.
        validate_option(
            r#"
            name = "retries"
            description = "How many times to try again."
            type = "integer"
            min = 0
            max = 10
            "#,
        )
        .expect("a bounded field needs no default");
    }

    /// A default is what a user gets for touching nothing, so a default that
    /// cannot be delivered is a backend that is broken on arrival and cannot be
    /// unbroken from the settings UI.
    #[test]
    fn a_default_that_cannot_be_sent_as_a_header_is_refused() {
        let err = validate_option(
            r#"
            name = "greeting"
            description = "How to open."
            default = "Hello,\nthere"
            "#,
        )
        .expect_err("a line break cannot ride in a header");
        assert!(
            matches!(err, ManifestError::UndeliverableDefault(ref n, _) if n == "greeting"),
            "got: {err}"
        );
    }

    #[test]
    fn a_bool_option_cannot_offer_choices() {
        let err = validate_option(
            r#"
            name = "tidy"
            description = "Tidy up."
            type = "bool"
            default = true
            choices = [true, false]
            "#,
        )
        .expect_err("a switch does not get a list");
        assert!(
            matches!(err, ManifestError::BoolWithChoices(ref n) if n == "tidy"),
            "got: {err}"
        );
    }

    #[test]
    fn a_choice_offered_twice_is_refused() {
        let err = validate_option(
            r#"
            name = "styling"
            description = "The register."
            choices = ["formal", "formal"]
            "#,
        )
        .expect_err("a duplicate row cannot be chosen");
        assert!(
            matches!(err, ManifestError::DuplicateChoice(ref n, ref c) if n == "styling" && c == "formal"),
            "got: {err}"
        );
    }

    /// Every manifest published before the field, and every option that is
    /// genuinely open-ended, declares no list and is unaffected.
    #[test]
    fn an_option_offering_nothing_is_left_alone() {
        validate_option(
            r#"
            name = "custom_model"
            description = "Any model name."
            default = "some-model"
            "#,
        )
        .expect("an open-ended option validates");
    }

    #[test]
    fn validates_a_correct_wasm_manifest() {
        let m = Manifest::parse(VALID).unwrap();
        validate(&m, &Version::new(1, 0, 0), "github.com/x/y", None).unwrap();
    }

    #[test]
    fn accepts_a_manifest_whose_id_matches_the_entry() {
        let m = Manifest::parse(&with_id("com.example.y")).unwrap();
        validate(
            &m,
            &Version::new(1, 0, 0),
            "github.com/x/y",
            Some("com.example.y"),
        )
        .expect("matching ids validate");
    }

    #[test]
    fn rejects_a_manifest_whose_id_differs_from_the_entry() {
        let m = Manifest::parse(&with_id("com.example.other")).unwrap();
        let err = validate(
            &m,
            &Version::new(1, 0, 0),
            "github.com/x/y",
            Some("com.example.y"),
        )
        .unwrap_err();
        assert!(matches!(err, ManifestError::IdMismatch(_, _)), "{err:?}");
    }

    #[test]
    fn rejects_a_manifest_with_no_id_when_the_entry_declares_one() {
        let m = Manifest::parse(VALID).unwrap();
        let err = validate(
            &m,
            &Version::new(1, 0, 0),
            "github.com/x/y",
            Some("com.example.y"),
        )
        .unwrap_err();
        assert!(matches!(err, ManifestError::IdMismatch(_, _)), "{err:?}");
    }

    /// A grandfathered entry declares no id, so the manifest is not pinned.
    #[test]
    fn accepts_any_id_when_the_entry_declares_none() {
        let m = Manifest::parse(VALID).unwrap();
        validate(&m, &Version::new(1, 0, 0), "github.com/x/y", None).expect("unpinned");
        let m = Manifest::parse(&with_id("com.example.y")).unwrap();
        validate(&m, &Version::new(1, 0, 0), "github.com/x/y", None).expect("unpinned");
    }

    /// The indexer fetches `backend.toml` from a backend's release, so it sees
    /// whatever released backends declare — including `provider`, which this
    /// workspace no longer reads. Accepting it is what keeps already-published
    /// backends in the index; rejecting it would silently drop them.
    ///
    /// The parse-level guarantee is pinned in `super-engine-spec`; this
    /// pins that the indexer's own `validate` gate passes it too.
    #[test]
    fn accepts_a_manifest_whose_model_declares_an_unread_provider() {
        let t = format!(
            "{VALID}
            [[models]]
            name = \"m1\"
            provider = \"local_model\"
            primary_language = \"en\"
            supported_languages = [\"en\"]
            supported_devices = [\"cpu\"]
            "
        );
        let m = Manifest::parse(&t).expect("a manifest declaring `provider` must still parse");
        validate(&m, &Version::new(1, 0, 0), "github.com/x/y", None)
            .expect("`provider` must not fail indexer validation");
        assert_eq!(m.models.len(), 1);
    }

    #[test]
    fn rejects_version_mismatch() {
        let m = Manifest::parse(VALID).unwrap();
        let err = validate(&m, &Version::new(2, 0, 0), "github.com/x/y", None).unwrap_err();
        assert!(matches!(err, ManifestError::VersionMismatch(_, _)));
    }

    #[test]
    fn rejects_source_mismatch() {
        let m = Manifest::parse(VALID).unwrap();
        let err = validate(&m, &Version::new(1, 0, 0), "github.com/other/repo", None).unwrap_err();
        assert!(matches!(err, ManifestError::SourceMismatch(_, _)));
    }

    #[test]
    fn accepts_monorepo_subpath_source() {
        let t = VALID.replace("github.com/x/y", "github.com/x/y/openai");
        let m = Manifest::parse(&t).unwrap();
        validate(&m, &Version::new(1, 0, 0), "github.com/x/y", None).unwrap();
    }

    #[test]
    fn rejects_source_that_only_shares_a_prefix_segment() {
        let t = VALID.replace("github.com/x/y", "github.com/x/yyy");
        let m = Manifest::parse(&t).unwrap();
        let err = validate(&m, &Version::new(1, 0, 0), "github.com/x/y", None).unwrap_err();
        assert!(matches!(err, ManifestError::SourceMismatch(_, _)));
    }

    #[test]
    fn unsafe_entrypoint_surfaces_as_parse_error() {
        // Exhaustive entrypoint guard cases are tested in the canonical
        // `super-engine-spec` crate; this only pins that the guard
        // surfaces as this crate's `ManifestError::Parse`.
        let t = r#"
            [backend]
            source = "github.com/x/y"
            name = "Y"
            version = "1.0.0"
            kind = "subprocess"
            entrypoint = "../escape"
            contract = "v1"
            description = "Test backend."
        "#;
        let err: ManifestError = Manifest::parse(t).unwrap_err().into();
        assert!(matches!(
            err,
            ManifestError::Parse(ParseError::UnsafeEntrypoint(_))
        ));
    }

    #[test]
    fn rejects_cuda_without_required_fields() {
        // Accel/cuda cross-field validation is enforced by `Manifest::parse`
        // itself (canonical in `super-engine-spec`); this only pins that
        // the guard surfaces as this crate's `ManifestError::Parse`.
        let t = r#"
            [backend]
            source = "github.com/x/y"
            name = "Y"
            version = "1.0.0"
            kind = "subprocess"
            entrypoint = "y"
            contract = "v1"
            description = "Test backend."
            license = "Apache-2.0"

            [[assets.subprocess]]
            file = "y.tar.gz"
            target = "x86_64-unknown-linux-gnu"
            accel = "cuda"
        "#;
        let err: ManifestError = Manifest::parse(t).unwrap_err().into();
        assert!(matches!(
            err,
            ManifestError::Parse(ParseError::CudaMissingMajor { .. })
        ));
    }

    /// A release may declare the `base_url` option, but not a value for it: the
    /// host it names is authorized for egress with the SSRF guard relaxed, which
    /// only the user may ask for. The registry is where that is refused — the
    /// daemon loads such a backend with the value dropped.
    #[test]
    fn rejects_a_base_url_default_but_accepts_the_option() {
        const BASE: &str = r#"
            [backend]
            source = "github.com/x/y"
            name = "Y"
            version = "1.0.0"
            kind = "wasm"
            entrypoint = "y.wasm"
            contract = "v1"
            description = "Test backend."
            license = "Apache-2.0"

            [assets]
            wasm = "y.wasm"

            [[options]]
            name = "base_url"
            description = "Endpoint."
            type = "string"
        "#;
        let m = Manifest::parse(BASE).unwrap();
        validate(&m, &Version::new(1, 0, 0), "github.com/x/y", None).unwrap();

        let m = Manifest::parse(&format!("{BASE}\ndefault = \"https://api.y.com\"\n")).unwrap();
        let err = validate(&m, &Version::new(1, 0, 0), "github.com/x/y", None).unwrap_err();
        assert!(
            matches!(err, ManifestError::BaseUrlDefault),
            "expected BaseUrlDefault, got {err:?}"
        );

        // Every other option keeps its default.
        let m =
            Manifest::parse(&BASE.replace(r#"name = "base_url""#, r#"name = "region""#)).unwrap();
        validate(&m, &Version::new(1, 0, 0), "github.com/x/y", None).unwrap();
    }

    #[test]
    fn accepts_cuda_with_major_but_no_sm() {
        let t = r#"
            [backend]
            source = "github.com/x/y"
            name = "Y"
            version = "1.0.0"
            kind = "subprocess"
            entrypoint = "y"
            contract = "v1"
            description = "Test backend."
            license = "Apache-2.0"

            [[assets.subprocess]]
            file = "y.tar.gz"
            target = "x86_64-unknown-linux-gnu"
            accel = "cuda"
            cuda_major = 13
        "#;
        let m = Manifest::parse(t).unwrap();
        validate(&m, &Version::new(1, 0, 0), "github.com/x/y", None).unwrap();
    }
}
