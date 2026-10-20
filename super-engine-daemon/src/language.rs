// SPDX-License-Identifier: GPL-3.0-only
//! Resolve the language a model is asked to work in: a per-model override,
//! else the daemon's global setting, else the model's own default.

/// Where the resolved language came from — surfaced to clients so the UI can
/// label it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanguageSource {
    Override,
    Global,
    Default,
}

impl LanguageSource {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Override => "override",
            Self::Global => "global",
            Self::Default => "default",
        }
    }
}

/// The outcome of resolving a language for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedLanguage {
    /// Value to send in the backend `language` field, or `None` to omit it
    /// (the model then uses its `primary_language`). A BCP-47 tag or `"auto"`.
    pub wire: Option<String>,
    /// Where `wire` came from (override / global / model default).
    pub source: LanguageSource,
}

fn has_region(tag: &str) -> bool {
    tag.contains('-')
}

fn base(tag: &str) -> &str {
    tag.split('-').next().unwrap_or(tag)
}

/// Primary subtags that name one language under two spellings, matched either
/// way round, so a tag reaches a model that declares the other spelling.
///
/// The first is a judgment call: IANA registers `fil` (Filipino) and `tl`
/// (Tagalog) as separate languages, but Filipino is standardized Tagalog, and
/// backends disagree on which to declare for one language — Qwen3-ASR's `fil`,
/// Whisper's and Deepgram's `tl` — while the global list offers `tl-PH`. The
/// rest are IANA's deprecated subtags and their `Preferred-Value`s, which older
/// tools still emit: Whisper names Javanese `jw`.
///
/// A macrolanguage is not the same language as each of its members, so none
/// is listed: `yue` (Cantonese) must not resolve to `zh`, nor `nn` (Nynorsk) to
/// `no`.
const EQUIVALENT_BASES: &[(&str, &str)] = &[
    ("fil", "tl"),
    ("he", "iw"),
    ("id", "in"),
    ("jv", "jw"),
    ("ro", "mo"),
    ("yi", "ji"),
];

/// `base`, then every other spelling of it.
fn base_spellings(base: &str) -> impl Iterator<Item = &str> {
    std::iter::once(base).chain(EQUIVALENT_BASES.iter().filter_map(move |&(a, b)| {
        if a == base {
            Some(b)
        } else if b == base {
            Some(a)
        } else {
            None
        }
    }))
}

/// The tags the global language setting accepts (`POST /settings/language`),
/// and what `GET /settings/language/list` publishes.
///
/// Region-qualified, with one exception: Chinese uses the ISO 15924 script
/// subtags `zh-Hans` / `zh-Hant`, since script — not region — is what
/// distinguishes Simplified from Traditional. A region is a country code, or UN
/// M.49 for a multi-country region (`es-419`).
///
/// Region-qualified is deliberate and is what makes one global setting work
/// across backends that disagree about granularity. A model may declare `en` or
/// `en-US` — that is the backend's choice — and [`adapt`] narrows a qualified
/// global to whichever the model actually serves. Publishing base codes instead
/// would throw away a distinction some models can use; publishing both would
/// offer the user two spellings of one answer.
///
/// A client cannot infer this list — not the vocabulary, and not which of `en`
/// and `en-US` to send — so a client that hardcodes its own is guessing at a
/// rule only the resolver here knows.
pub const GLOBAL_LANGUAGES: &[&str] = &[
    "af-ZA", "ar-EG", "ar-SA", "bn-BD", "bg-BG", "ca-ES", "zh-Hans", "zh-Hant", "hr-HR", "cs-CZ",
    "da-DK", "nl-NL", "en-AU", "en-CA", "en-IN", "en-GB", "en-US", "et-EE", "fi-FI", "fr-BE",
    "fr-CA", "fr-FR", "de-AT", "de-DE", "de-CH", "el-GR", "he-IL", "hi-IN", "hu-HU", "id-ID",
    "it-IT", "ja-JP", "ko-KR", "ms-MY", "no-NO", "fa-IR", "pl-PL", "pt-BR", "pt-PT", "ro-RO",
    "ru-RU", "sk-SK", "es-419", "es-MX", "es-ES", "es-US", "sw-KE", "sv-SE", "tl-PH", "ta-IN",
    "te-IN", "th-TH", "tr-TR", "uk-UA", "ur-PK", "vi-VN", "cy-GB",
];

/// Whether `tag` is one the global setting accepts: a published tag, or the
/// reserved `auto`.
#[must_use]
pub fn is_offered_globally(tag: &str) -> bool {
    tag == "auto" || GLOBAL_LANGUAGES.contains(&tag)
}

/// Match a chosen tag against a model's `supported_languages` with region rules.
/// Returns the value to send — always in the model's own spelling — or `None`
/// to omit.
fn adapt(tag: &str, supported: &[String]) -> Option<String> {
    if tag == "auto" {
        return Some("auto".to_string());
    }
    let declared = |t: &str| supported.iter().any(|s| s == t);
    let b = base(tag);
    let qualifiers = &tag[b.len()..];
    // Exact (base or region), under any spelling of the language: tl-PH
    // reaches a model declaring fil-PH, and tl one declaring fil.
    if let Some(t) = base_spellings(b)
        .map(|s| format!("{s}{qualifiers}"))
        .find(|t| declared(t))
    {
        return Some(t);
    }
    // No exact match: a region tag falls back to the base language when the
    // model lists it (e.g. es-MX → es), even if the model also carries region
    // variants for that language (e.g. a model listing `es` + `es-419`). Only when
    // the base isn't supported either is the language unsupported → omit.
    if has_region(tag)
        && let Some(b) = base_spellings(b).find(|b| declared(b))
    {
        return Some(b.to_string());
    }
    None
}

/// Resolve the effective language for the active model. See the spec's
/// resolution pseudocode.
#[must_use]
pub fn resolve_language(
    multilingual: bool,
    override_: Option<&str>,
    global: Option<&str>,
    supported: &[String],
) -> ResolvedLanguage {
    if !multilingual {
        return ResolvedLanguage {
            wire: None,
            source: LanguageSource::Default,
        };
    }
    if let Some(tag) = override_
        && let Some(wire) = adapt(tag, supported)
    {
        return ResolvedLanguage {
            wire: Some(wire),
            source: LanguageSource::Override,
        };
    }
    if let Some(tag) = global
        && let Some(wire) = adapt(tag, supported)
    {
        return ResolvedLanguage {
            wire: Some(wire),
            source: LanguageSource::Global,
        };
    }
    ResolvedLanguage {
        wire: None,
        source: LanguageSource::Default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn non_multilingual_never_sends_language() {
        let r = resolve_language(false, Some("es"), Some("fr"), &s(&["en"]));
        assert_eq!(r.wire, None);
        assert_eq!(r.source, LanguageSource::Default);
    }

    #[test]
    fn override_exact_wins() {
        let r = resolve_language(true, Some("fr"), Some("es"), &s(&["en", "fr", "es"]));
        assert_eq!(r.wire.as_deref(), Some("fr"));
        assert_eq!(r.source, LanguageSource::Override);
    }

    #[test]
    fn override_auto_always_applies() {
        let r = resolve_language(true, Some("auto"), None, &s(&["en"]));
        assert_eq!(r.wire.as_deref(), Some("auto"));
        assert_eq!(r.source, LanguageSource::Override);
    }

    #[test]
    fn override_unsupported_falls_to_global() {
        let r = resolve_language(true, Some("xx"), Some("es"), &s(&["en", "es"]));
        assert_eq!(r.wire.as_deref(), Some("es"));
        assert_eq!(r.source, LanguageSource::Global);
    }

    #[test]
    fn global_exact_when_no_override() {
        let r = resolve_language(true, None, Some("es-419"), &s(&["en", "es-419"]));
        assert_eq!(r.wire.as_deref(), Some("es-419"));
        assert_eq!(r.source, LanguageSource::Global);
    }

    #[test]
    fn global_region_strips_for_region_agnostic_model() {
        // Model lists base `es`, no region variants → strip region.
        let r = resolve_language(true, None, Some("es-MX"), &s(&["en", "es"]));
        assert_eq!(r.wire.as_deref(), Some("es"));
        assert_eq!(r.source, LanguageSource::Global);
    }

    #[test]
    fn global_region_strips_to_base_even_with_region_siblings() {
        // Model lists base `es` AND a region variant (`es-419`).
        // A picked es-MX strips to base `es` rather than falling back to default.
        let r = resolve_language(true, None, Some("es-MX"), &s(&["en", "es", "es-419"]));
        assert_eq!(r.wire.as_deref(), Some("es"));
        assert_eq!(r.source, LanguageSource::Global);
    }

    #[test]
    fn global_region_falls_back_when_base_unsupported() {
        // Model carries only region variants for `es` (`es-419`, `es-ES`) and no
        // base `es`, and lacks es-MX → the language is unsupported → default.
        let r = resolve_language(true, None, Some("es-MX"), &s(&["en-US", "es-419", "es-ES"]));
        assert_eq!(r.wire, None);
        assert_eq!(r.source, LanguageSource::Default);
    }

    #[test]
    fn global_unrecognized_base_tag_falls_back() {
        let r = resolve_language(true, None, Some("ja"), &s(&["en", "es"]));
        assert_eq!(r.wire, None);
        assert_eq!(r.source, LanguageSource::Default);
    }

    #[test]
    fn global_tagalog_reaches_a_model_declaring_filipino() {
        // The global list offers tl-PH; Qwen3-ASR declares `fil`.
        let r = resolve_language(true, None, Some("tl-PH"), &s(&["en", "fil"]));
        assert_eq!(r.wire.as_deref(), Some("fil"));
        assert_eq!(r.source, LanguageSource::Global);
    }

    #[test]
    fn equivalent_spellings_match_either_way_and_keep_the_model_spelling() {
        let r = resolve_language(true, Some("fil-PH"), None, &s(&["en", "tl"]));
        assert_eq!(r.wire.as_deref(), Some("tl"));
        let r = resolve_language(true, Some("fil"), None, &s(&["en", "tl"]));
        assert_eq!(r.wire.as_deref(), Some("tl"));
        let r = resolve_language(true, None, Some("he-IL"), &s(&["en", "iw"]));
        assert_eq!(r.wire.as_deref(), Some("iw"));
        let r = resolve_language(true, Some("jv"), None, &s(&["en", "jw"]));
        assert_eq!(r.wire.as_deref(), Some("jw"));
    }

    #[test]
    fn equivalent_spelling_keeps_the_region() {
        let r = resolve_language(true, None, Some("tl-PH"), &s(&["en", "fil", "fil-PH"]));
        assert_eq!(r.wire.as_deref(), Some("fil-PH"));
    }

    #[test]
    fn own_spelling_wins_when_the_model_declares_both() {
        let r = resolve_language(true, None, Some("tl-PH"), &s(&["fil", "tl"]));
        assert_eq!(r.wire.as_deref(), Some("tl"));
    }

    #[test]
    fn macrolanguage_members_are_not_equivalent() {
        // Cantonese is not Chinese to a model, nor Nynorsk Norwegian.
        let r = resolve_language(true, None, Some("zh-Hant"), &s(&["en", "yue"]));
        assert_eq!(r.wire, None);
        let r = resolve_language(true, None, Some("no-NO"), &s(&["en", "nn"]));
        assert_eq!(r.wire, None);
    }

    #[test]
    fn each_base_has_at_most_one_other_spelling() {
        let mut bases: Vec<&str> = EQUIVALENT_BASES.iter().flat_map(|&(a, b)| [a, b]).collect();
        let n = bases.len();
        bases.sort_unstable();
        bases.dedup();
        assert_eq!(bases.len(), n, "a base listed twice");
    }

    #[test]
    fn unset_is_default() {
        let r = resolve_language(true, None, None, &s(&["en", "es"]));
        assert_eq!(r.wire, None);
        assert_eq!(r.source, LanguageSource::Default);
    }
}
