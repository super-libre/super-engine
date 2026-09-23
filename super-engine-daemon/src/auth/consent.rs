// SPDX-License-Identifier: GPL-3.0-only
//! Asking the user whether a caller may have a token.

use crate::auth::identity::PeerIdentity;
use std::collections::HashMap;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use super_engine_protocol::{ProductSpec, consent};

/// Global cap of one on-screen consent popup at a time. See
/// [`ask_user_for_consent`] — without it a same-uid client could drive hundreds
/// of concurrent exclusive-keyboard dialogs (255 distinct consent keys) and lock
/// the desktop (audit 2 Tier 3 #10).
static CONSENT_POPUP: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

/// Identifies the consent flow uniquely: (`identity`, normalized `scopes`).
/// The user verifies a *binary* (or a sandboxed app), not a self-reported
/// display name, so the deny / dedup key is keyed on the kernel-resolved
/// [`PeerIdentity`] plus the requested scope set (sorted + deduped via
/// [`normalize_scopes`] so request order doesn't matter). `app_name` is
/// shown in the popup but isn't part of the identity.
pub type ConsentKey = (PeerIdentity, Vec<String>);
pub type ConsentLock = Arc<tokio::sync::Mutex<()>>;

/// Sort + dedup a requested scope list so the consent key and the
/// granted set are independent of the order the client listed them.
#[must_use]
pub fn normalize_scopes(scopes: &[String]) -> Vec<String> {
    let mut v = scopes.to_vec();
    v.sort();
    v.dedup();
    v
}

/// Per-`(exe_path, scope)` async mutex registry used by the
/// `/auth/request` handler to dedup concurrent first-time consent
/// requests. Without this, two clients that ping the daemon at the same
/// time on a fresh install would each spawn their own consent popup;
/// with it, the second blocks until the first finishes and then
/// short-circuits via the reuse-scan against the now-minted token.
///
/// The map is pruned via [`Self::release`] after the auth flow
/// completes so a malicious client can't drive unbounded memory
/// growth by spamming /auth/request with rotating keys.
#[derive(Clone, Default)]
pub struct ConsentLocks {
    inner: Arc<Mutex<HashMap<ConsentKey, ConsentLock>>>,
}

impl ConsentLocks {
    /// The lock for `key`, shared with every other request for the same key.
    ///
    /// # Panics
    /// If a thread panicked while holding the registry's lock.
    #[must_use]
    pub fn lock_for(&self, key: ConsentKey) -> ConsentLock {
        let mut map = self.inner.lock().unwrap();
        map.entry(key)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Drop the registry entry for `key` if no other task is still
    /// holding the `ConsentLock`. Called from the `auth_request`
    /// handler after the consent flow finishes — success or denial.
    /// `strong_count == 2` means exactly the map and our local clone
    /// hold references; anything higher means another in-flight
    /// `auth_request` for the same key is still waiting on the same
    /// mutex and we leave the entry in place for it.
    ///
    /// # Panics
    /// If a thread panicked while holding the registry's lock.
    pub fn release(&self, key: &ConsentKey, lock: &ConsentLock) {
        let mut map = self.inner.lock().unwrap();
        // Our `lock` reference plus the one inside the map. If
        // anything else is still holding, leave it.
        if Arc::strong_count(lock) <= 2 {
            map.remove(key);
        }
    }
}

/// What the consent dialog needs from the product: its name, and what each
/// of its scopes grants.
#[derive(Clone, Copy, Debug)]
pub struct ConsentDialog {
    pub product: &'static ProductSpec,
    /// The lines the dialog lists for a request's scopes: the union of each
    /// scope's own, in order and without repeats. The macOS dialog renders
    /// these; on Linux the product's consent helper renders the same table
    /// itself.
    pub describe_scopes: fn(&[String]) -> Vec<&'static str>,
}

/// The user's answer, or why there is none.
#[derive(Clone, Copy, Debug)]
pub enum ConsentDecision {
    Allow,
    Deny,
    Dismissed,
    PopupFailed,
}

/// Read the consent helper's single-line verdict from its stdout. The helper
/// writes one of [`consent::ALLOW`] / [`consent::DENY`] /
/// [`consent::DISMISSED`] and exits.
async fn read_consent_decision(stdout: tokio::process::ChildStdout) -> ConsentDecision {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let mut reader = BufReader::new(stdout).lines();
    match reader.next_line().await {
        Ok(Some(line)) => match line.trim() {
            consent::ALLOW => ConsentDecision::Allow,
            consent::DENY => ConsentDecision::Deny,
            _ => ConsentDecision::Dismissed,
        },
        _ => ConsentDecision::Dismissed,
    }
}

/// Put the consent question on screen and hand back the running dialog.
///
/// The caller owns the policy around it — the one-popup-at-a-time permit, the
/// 60-second deadline, and the reap — so all this does is start a process that
/// will print one of `allow` / `deny` / `dismissed` to stdout. `None` means no
/// dialog could be shown at all, which the caller reports as
/// [`ConsentDecision::PopupFailed`]: distinct from a denial, because the user
/// was never asked.
///
/// Linux spawns the product's consent helper (`super-stt-consent`), installed
/// beside the daemon; see `locate_consent_helper` for why it is only ever
/// looked for there.
#[cfg(target_os = "linux")]
#[expect(
    clippy::unused_async,
    reason = "shares a signature with the macOS arm, which awaits writing its script to osascript"
)]
async fn spawn_consent_dialog(
    dialog: &ConsentDialog,
    app_name: &str,
    scopes: &[String],
    identity: &PeerIdentity,
) -> Option<tokio::process::Child> {
    let product = dialog.product;
    // `locate_consent_helper` already logs a specific reason on every
    // failure path (missing / un-canonicalizable / failed metadata check),
    // so we don't emit a second, redundant warning here.
    let helper = locate_consent_helper(product)?;

    let mut cmd = tokio::process::Command::new(&helper);
    cmd.env(product.env(consent::APP_NAME), app_name)
        .env(product.env(consent::SCOPES), scopes.join(" "));
    match identity {
        PeerIdentity::Native {
            exe_path,
            flatpak_app_id,
        } => {
            cmd.env(
                product.env(consent::EXE_PATH),
                exe_path.to_string_lossy().as_ref(),
            )
            // Set only for a sandboxed peer, so the dialog can name the app
            // the user actually installed instead of a path inside its
            // sandbox.
            .envs(
                flatpak_app_id
                    .as_ref()
                    .map(|id| (product.env(consent::FLATPAK_APP_ID), id.clone())),
            );
        }
        // A web peer sets the origin variable *instead of* the exe path, never
        // alongside it. The helper decides which dialog to show by which one it
        // was given, so sending both would leave the user reading a sentence
        // about a binary when a website is what is asking.
        PeerIdentity::Web { origin } => {
            cmd.env(product.env(consent::WEB_ORIGIN), origin);
        }
    }
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        // The timeout in the caller only reaps the helper while *that* request
        // is still running. A client that exits mid-consent cancels it, which
        // drops the future and this `Child` with it — and a dropped
        // `tokio::process::Child` leaves the process alone unless asked not
        // to. Without this the dialog is orphaned for the life of the
        // session, holding an exclusive-keyboard layer surface and ~40 MB
        // that nothing is left to kill.
        .kill_on_drop(true);

    match cmd.spawn() {
        Ok(c) => Some(c),
        Err(e) => {
            log::warn!("failed to spawn {}: {e}", helper.display());
            None
        }
    }
}

/// The `AppleScript` behind the macOS consent dialog.
///
/// It builds no strings: both the message and the title arrive as `argv`
/// items, so nothing a caller can put in an app name is ever parsed as
/// `AppleScript`. The two-step — compose in Rust, display in `AppleScript` — is
/// the whole reason this is `osascript -` with arguments rather than
/// `osascript -e` with the text interpolated in.
///
/// `giving up after 55` sits just inside the caller's 60-second deadline so
/// an abandoned dialog reports itself as dismissed and exits, instead of
/// being killed with the question still on screen.
///
/// There is deliberately no `cancel button`: naming one would make Escape and
/// a Deny click raise the same `-128`, and the daemon would lose the
/// difference between "the user refused" (sticky) and "the user walked away"
/// (not sticky).
#[cfg(target_os = "macos")]
const CONSENT_APPLESCRIPT: &str = r#"on run argv
	set dialogText to item 1 of argv
	set dialogTitle to item 2 of argv
	try
		set answer to display dialog dialogText with title dialogTitle buttons {"Deny", "Allow"} default button "Deny" with icon caution giving up after 55
	on error number -128
		return "dismissed"
	end try
	if gave up of answer then return "dismissed"
	if button returned of answer is "Allow" then return "allow"
	return "deny"
end run
"#;

/// Absolute path to the system `AppleScript` interpreter.
///
/// Absolute, never `osascript` off `PATH`, for the reason
/// the Linux helper lookup spells out: anyone who can prepend a writable
/// directory to the daemon's `PATH` could otherwise answer the consent
/// question on the user's behalf. `/usr/bin` is on the signed system volume,
/// which is read-only and cryptographically sealed.
#[cfg(target_os = "macos")]
const OSASCRIPT: &str = "/usr/bin/osascript";

/// See the Linux [`spawn_consent_dialog`].
///
/// macOS has no consent helper to spawn — the helper is a libcosmic
/// application and libcosmic does not build here — so the question goes up
/// through `osascript` instead. The user-visible sentences come from
/// [`ConsentDialog::describe_scopes`], which is the table the Linux helper
/// renders too, so the two platforms describe a grant identically.
#[cfg(target_os = "macos")]
async fn spawn_consent_dialog(
    dialog: &ConsentDialog,
    app_name: &str,
    scopes: &[String],
    identity: &PeerIdentity,
) -> Option<tokio::process::Child> {
    use tokio::io::AsyncWriteExt as _;

    let message = consent_dialog_text(dialog, app_name, scopes, identity);

    let mut child = match tokio::process::Command::new(OSASCRIPT)
        // `-` reads the script from stdin; everything after it is `argv`.
        .arg("-")
        .arg(&message)
        .arg(format!("Allow access to {}?", dialog.product.display_name))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        // See the Linux arm: a cancelled request drops the `Child`, and a
        // dropped child is not killed unless asked.
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            log::warn!("failed to spawn {OSASCRIPT} for the consent dialog: {e}");
            return None;
        }
    };

    // Hand over the script and close the pipe — `osascript -` reads stdin to
    // EOF before it will run anything, so the dialog does not appear until
    // this drop happens.
    let Some(mut stdin) = child.stdin.take() else {
        log::warn!("osascript child had no stdin pipe; cannot deliver the consent script");
        return None;
    };
    if let Err(e) = stdin.write_all(CONSENT_APPLESCRIPT.as_bytes()).await {
        log::warn!("failed to write the consent script to osascript: {e}");
        return None;
    }
    drop(stdin);

    Some(child)
}

/// Compose what the macOS dialog says.
///
/// Mirrors the structure of the libcosmic helper's dialog: who is asking, how
/// they were identified, and the union of what the requested scopes grant.
///
/// `app_name` is the one part of this the *caller* chose, and the dialog is a
/// single text field rather than a set of labelled widgets — so an app name
/// carrying newlines could otherwise forge the `Executable:` line beneath it
/// and take credit for a binary the user trusts. [`sanitize_display_name`]
/// is what stops that, and is the reason this is assembled here rather than
/// inline at the call site.
#[cfg(target_os = "macos")]
fn consent_dialog_text(
    dialog: &ConsentDialog,
    app_name: &str,
    scopes: &[String],
    identity: &PeerIdentity,
) -> String {
    use std::fmt::Write as _;

    let product = dialog.product.display_name;
    let mut text = String::new();
    match identity {
        PeerIdentity::Native {
            exe_path,
            flatpak_app_id: _,
        } => {
            let name = sanitize_display_name(app_name);
            let name = if name.is_empty() {
                "An application".to_string()
            } else {
                name
            };
            let _ = writeln!(text, "{name} wants access to {product}.");
            let _ = writeln!(text);
            // Not sanitized, and does not need to be: this is the path the
            // kernel reported for the calling process, not anything the
            // caller wrote.
            let _ = writeln!(text, "Executable:  {}", exe_path.display());
        }
        PeerIdentity::Web { origin } => {
            // The origin has already been matched against the user's
            // allowlist by the origin gate, so it is one of a small set of
            // strings the user typed themselves.
            let _ = writeln!(text, "{origin} wants access to {product}.");
            let _ = writeln!(text);
            let _ = writeln!(
                text,
                "Your browser reports which website this is. That is a weaker check than \
                 {product} does for installed programs."
            );
        }
    }

    let _ = writeln!(text);
    let _ = writeln!(text, "This will allow it to:");
    for line in (dialog.describe_scopes)(scopes) {
        let _ = writeln!(text, "  •  {line}");
    }
    text
}

/// Longest app name the dialog will show, in characters.
///
/// Long enough for any real product name; short enough that a name cannot
/// push the `Executable:` line and the permission list off the bottom of the
/// dialog, which would leave the user approving a question they cannot see
/// the whole of.
#[cfg(target_os = "macos")]
const MAX_DISPLAY_NAME: usize = 64;

/// Flatten a caller-supplied app name to one line of printable text.
///
/// Control characters — newlines above all — become spaces rather than being
/// dropped, so `"Foo\nExecutable:  /usr/bin/trusted"` reads as one visibly odd
/// name instead of silently becoming two convincing lines. Runs of whitespace
/// collapse for the same reason: spaces are as good as newlines for pushing
/// text around once the font is proportional.
#[cfg(target_os = "macos")]
fn sanitize_display_name(name: &str) -> String {
    let flattened: String = name
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let mut out = String::new();
    for word in flattened.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
        if out.chars().count() >= MAX_DISPLAY_NAME {
            break;
        }
    }
    if out.chars().count() > MAX_DISPLAY_NAME {
        out = out.chars().take(MAX_DISPLAY_NAME - 1).collect();
        out.push('…');
    }
    out
}

/// Put the consent question on screen and wait up to a minute for the answer.
pub async fn ask_user_for_consent(
    dialog: &ConsentDialog,
    app_name: &str,
    scopes: &[String],
    identity: &PeerIdentity,
) -> ConsentDecision {
    // Serialize popups globally: at most one consent dialog on screen at a time
    // (audit 2 Tier 3 #10). `/auth/request` is unauthenticated and outside the
    // rate limiter, and the 8 scopes yield 255 distinct `(exe, scopes)` consent
    // keys — each bypassing the per-key dedup — so without this cap a same-uid
    // process could stack hundreds of concurrent exclusive-keyboard overlays and
    // lock the desktop. Excess requests wait for the permit rather than opening
    // in parallel. Acquired before the spawn and held while the dialog is on
    // screen; released before the untimed reap below so a wedged helper can't
    // wedge all consent.
    let Ok(popup_permit) = CONSENT_POPUP.acquire().await else {
        return ConsentDecision::PopupFailed; // semaphore closed (never in practice)
    };

    let Some(mut child) = spawn_consent_dialog(dialog, app_name, scopes, identity).await else {
        drop(popup_permit);
        return ConsentDecision::PopupFailed;
    };

    let Some(stdout) = child.stdout.take() else {
        return ConsentDecision::PopupFailed;
    };

    let result = tokio::time::timeout(Duration::from_mins(1), read_consent_decision(stdout)).await;
    let _ = child.start_kill();
    // The dialog is being torn down, so release the global one-popup permit
    // *before* the reap. `child.wait()` is untimed; holding the sole global
    // permit across it would let a helper that somehow doesn't reap promptly
    // (a pathological uninterruptible-sleep) wedge all consent daemon-wide.
    // Releasing first keeps the popup cap intact while the reap still completes.
    drop(popup_permit);
    let _ = child.wait().await;

    result.unwrap_or(ConsentDecision::Dismissed)
}

/// Basenames of the first-party client binaries that skip the consent
/// popup when co-located with the daemon binary: the product's app, CLI and
/// COSMIC applet (`super-stt-app`, `super-stt-cli`, `super-stt-cosmic-applet`).
/// See [`is_official_client`] for the full trust check.
fn official_client_names(product: &ProductSpec) -> [String; 3] {
    ["app", "cli", "cosmic-applet"].map(|client| format!("{}-{client}", product.slug))
}

/// First-party trust check: does `exe_path` denote one of our own
/// client binaries, installed alongside the daemon binary itself?
///
/// Mirrors the consent-helper security model — co-location
/// with the daemon binary plus the same ownership/permission
/// verification. Writing to the daemon's install directory is already
/// sufficient to replace the daemon, so trusting exact-named sibling
/// binaries adds no new attack surface. Returns a plain bool: failure
/// is the common case (every third-party client) and is deliberately
/// not logged here — the caller logs the rare success.
#[must_use]
pub fn is_official_client(product: &ProductSpec, identity: &PeerIdentity) -> bool {
    let PeerIdentity::Native {
        exe_path,
        flatpak_app_id,
    } = identity
    else {
        // A web peer is never first-party. The whole check below is about a
        // binary on this filesystem, and a page has none — there is nothing
        // to canonicalize and no ownership to verify, so the only safe answer
        // is the consent popup. A site calling itself `super-stt-app` must not
        // get within reach of the short-circuit.
        return false;
    };
    // A sandboxed peer is never first-party, whatever its path says. The
    // check below canonicalizes the path against *our* filesystem, and a
    // sandbox is free to put its own binary at /usr/local/bin/super-stt-app;
    // that path would then resolve to the real host binary, pass every test
    // here, and auto-approve a stranger with no popup at all.
    if flatpak_app_id.is_some() {
        return false;
    }
    let Ok(daemon_exe) = std::env::current_exe() else {
        return false;
    };
    let Some(daemon_dir) = daemon_exe.parent() else {
        return false;
    };
    is_official_client_in(product, daemon_dir, exe_path)
}

/// Testable core of [`is_official_client`] with the daemon's own
/// directory injected. Fail-closed on every non-verifiable branch: a
/// replaced-on-disk exe (`/proc/<pid>/exe` → "… (deleted)") or a
/// symlink resolving outside `daemon_dir` fails canonicalization or
/// the parent check and falls through to the normal consent flow.
fn is_official_client_in(product: &ProductSpec, daemon_dir: &Path, exe_path: &Path) -> bool {
    let (Ok(resolved), Ok(daemon_dir)) = (exe_path.canonicalize(), daemon_dir.canonicalize())
    else {
        return false;
    };
    let Some(name) = resolved.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if !official_client_names(product).iter().any(|n| n == name) {
        return false;
    }
    if resolved.parent() != Some(daemon_dir.as_path()) {
        return false;
    }
    verify_helper_metadata(&resolved).is_ok()
}

/// Find the consent helper.
///
/// **Security model.** The helper is only ever looked for **alongside the
/// daemon binary itself**. We deliberately do NOT fall back to `PATH`
/// because doing so would let any attacker who can prepend a writable
/// directory to the daemon's `PATH` (a classic privilege-escalation
/// vector) substitute their own helper. Forcing co-location bounds the
/// attack surface to "whoever can write to the directory holding the
/// daemon binary" — which is the same threshold required to replace the
/// daemon itself, so we don't make consent any easier to subvert than
/// the daemon's own integrity.
///
/// On top of that, before returning the path:
/// - We `canonicalize()` it, so symlink-swap shenanigans don't help.
/// - We verify the resolved file is owned by root or the daemon's
///   effective uid (catches "another local user dropped a helper they
///   own into the install dir").
/// - We verify it isn't world-writable.
#[cfg(target_os = "linux")]
fn locate_consent_helper(product: &ProductSpec) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let helper = product.consent_helper();
    let candidate = dir.join(&helper);
    if !candidate.exists() {
        log::warn!(
            "{helper} not found alongside daemon binary at {}; \
             auth_request will be denied with popup_failed",
            candidate.display()
        );
        return None;
    }

    let resolved = match candidate.canonicalize() {
        Ok(p) => p,
        Err(e) => {
            log::warn!(
                "failed to canonicalize consent helper path {}: {e}",
                candidate.display()
            );
            return None;
        }
    };

    if let Err(reason) = verify_helper_metadata(&resolved) {
        log::warn!(
            "consent helper at {} rejected: {reason}",
            resolved.display()
        );
        return None;
    }

    Some(resolved)
}

/// Verify the helper's file metadata is consistent with "trusted binary
/// installed by the user". Returns Err with a static reason on
/// rejection.
#[cfg(unix)]
fn verify_helper_metadata(path: &Path) -> Result<(), &'static str> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(path).map_err(|_| "cannot stat helper")?;
    let our_uid = unsafe { libc::geteuid() };
    check_helper_metadata(metadata.uid(), our_uid, metadata.mode())
}

/// Testable core of [`verify_helper_metadata`]. Trust binaries owned by
/// the daemon's own uid (source/dev installs) or by root (the packaged
/// /usr/local/bin // /usr/bin install) — whoever controls root already
/// controls the daemon binary itself, so root ownership adds no new
/// attack surface. Anything else is another local user's drop-in.
#[cfg(unix)]
fn check_helper_metadata(owner_uid: u32, our_uid: u32, mode: u32) -> Result<(), &'static str> {
    if owner_uid != our_uid && owner_uid != 0 {
        return Err("helper not owned by root or the daemon's effective uid");
    }
    // Reject world-writable helpers — anyone could swap them out.
    if mode & 0o002 != 0 {
        return Err("helper is world-writable");
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_helper_metadata(_: &Path) -> Result<(), &'static str> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The macOS dialog is one text field, so the app name — the one part of
    /// it the *caller* chooses — is the only place a forged line could come
    /// from. These pin the flattening that prevents it.
    #[cfg(target_os = "macos")]
    mod display_name {
        use super::super::PeerIdentity;
        use super::super::{
            ConsentDialog, MAX_DISPLAY_NAME, consent_dialog_text, sanitize_display_name,
        };

        /// A dialog for Super STT that describes `status` the way its table
        /// does.
        fn dialog() -> ConsentDialog {
            fn describe(_: &[String]) -> Vec<&'static str> {
                vec!["Read which speech-to-text model and device are currently active"]
            }
            ConsentDialog {
                product: &super_engine_protocol::SUPER_STT,
                describe_scopes: describe,
            }
        }
        use std::path::PathBuf;

        /// The attack this function exists for: an app name carrying a
        /// newline and a plausible `Executable:` line, which in a plain text
        /// field would read as the daemon's own attestation about the
        /// caller's binary.
        #[test]
        fn a_newline_cannot_forge_a_second_line() {
            let forged = sanitize_display_name("Evil\nExecutable:  /usr/local/bin/super-stt-app");
            assert!(!forged.contains('\n'), "{forged:?} still spans two lines");
            assert_eq!(
                forged, "Evil Executable: /usr/local/bin/super-stt-app",
                "the text should survive, visibly, on one line"
            );
        }

        /// Every control character, not just `\n`. A carriage return alone
        /// repositions the cursor in some renderers, and a vertical tab is a
        /// line break in others.
        #[test]
        fn every_control_character_is_flattened() {
            for c in ['\n', '\r', '\t', '\u{000b}', '\u{000c}', '\u{0085}'] {
                let out = sanitize_display_name(&format!("a{c}b"));
                assert_eq!(out, "a b", "control character {c:?} survived");
            }
        }

        /// A name long enough to push the rest of the dialog off screen is
        /// cut, and marked as cut.
        #[test]
        fn an_over_long_name_is_truncated() {
            let out = sanitize_display_name(&"x".repeat(MAX_DISPLAY_NAME * 3));
            assert!(out.chars().count() <= MAX_DISPLAY_NAME, "{out:?}");
            assert!(out.ends_with('…'), "truncation should be visible: {out:?}");
        }

        /// An empty or blank name yields an empty string rather than
        /// whitespace, so the caller's "An application" fallback triggers.
        #[test]
        fn a_blank_name_is_empty() {
            assert_eq!(sanitize_display_name(""), "");
            assert_eq!(sanitize_display_name("   \n\t "), "");
        }

        /// End to end: the composed dialog must name the kernel-reported
        /// executable exactly once, however hard the app name tries to add
        /// another.
        #[test]
        fn the_dialog_carries_one_executable_line() {
            let identity = PeerIdentity::Native {
                exe_path: PathBuf::from("/usr/bin/curl"),
                flatpak_app_id: None,
            };
            let text = consent_dialog_text(
                &dialog(),
                "Evil\nExecutable:  /usr/local/bin/super-stt-app",
                &["status".to_string()],
                &identity,
            );
            assert_eq!(
                text.lines()
                    .filter(|l| l.starts_with("Executable:"))
                    .count(),
                1,
                "exactly one line may claim to be the executable:\n{text}"
            );
            assert!(text.contains("Executable:  /usr/bin/curl"), "{text}");
            // And the scope's description is present, from the product's
            // table.
            assert!(
                text.contains("Read which speech-to-text model and device are currently active"),
                "{text}"
            );
        }

        /// A blank name falls back to a neutral label rather than leaving the
        /// sentence starting with "wants access".
        #[test]
        fn a_blank_name_becomes_a_neutral_label() {
            let identity = PeerIdentity::Native {
                exe_path: PathBuf::from("/usr/bin/curl"),
                flatpak_app_id: None,
            };
            let text = consent_dialog_text(&dialog(), "  ", &["status".to_string()], &identity);
            assert!(
                text.starts_with("An application wants access to Super STT."),
                "{text}"
            );
        }
    }

    /// `check_helper_metadata`: the ownership/permission gate shared by
    /// the consent-helper lookup and the official-client trust check.
    mod helper_metadata {
        use super::super::check_helper_metadata;

        #[test]
        fn owned_by_daemon_uid_is_trusted() {
            assert!(check_helper_metadata(1000, 1000, 0o755).is_ok());
        }

        #[test]
        fn root_owned_is_trusted() {
            // The packaged install (/usr/local/bin, /usr/bin) is
            // root-owned; root could already replace the daemon binary
            // itself, so this adds no new attack surface.
            assert!(check_helper_metadata(0, 1000, 0o755).is_ok());
        }

        #[test]
        fn other_local_user_is_rejected() {
            assert!(check_helper_metadata(1001, 1000, 0o755).is_err());
        }

        #[test]
        fn world_writable_is_rejected_even_when_root_owned() {
            assert!(check_helper_metadata(0, 1000, 0o757).is_err());
        }
    }

    #[test]
    fn normalize_sorts_and_dedups() {
        let got = normalize_scopes(&[
            "transcribe".to_string(),
            "status".to_string(),
            "transcribe".to_string(),
        ]);
        assert_eq!(got, vec!["status".to_string(), "transcribe".to_string()]);
    }

    #[test]
    fn normalize_is_order_independent() {
        let a = normalize_scopes(&["settings".to_string(), "status".to_string()]);
        let b = normalize_scopes(&["status".to_string(), "settings".to_string()]);
        assert_eq!(a, b, "request order must not change the consent key");
    }

    /// First-party trust check (`is_official_client_in`): exact-name
    /// allowlist + co-location with the daemon dir + metadata
    /// verification, fail-closed on every non-verifiable branch.
    mod official_client {
        use super::super::is_official_client_in as in_dir;
        use super_engine_protocol::{SUPER_STT, SUPER_TTS};

        fn is_official_client_in(daemon_dir: &Path, exe_path: &Path) -> bool {
            in_dir(&SUPER_STT, daemon_dir, exe_path)
        }
        use std::os::unix::fs::PermissionsExt;
        use std::path::{Path, PathBuf};

        fn write_executable(dir: &Path, name: &str, mode: u32) -> PathBuf {
            let path = dir.join(name);
            std::fs::write(&path, b"\x7fELF").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            path
        }

        #[test]
        fn official_name_co_located_is_trusted() {
            let dir = tempfile::tempdir().unwrap();
            let app = write_executable(dir.path(), "super-stt-app", 0o755);
            assert!(is_official_client_in(dir.path(), &app));
        }

        #[test]
        fn unlisted_name_co_located_is_rejected() {
            let dir = tempfile::tempdir().unwrap();
            let other = write_executable(dir.path(), "super-stt-extra", 0o755);
            assert!(
                !is_official_client_in(dir.path(), &other),
                "co-location alone must not confer trust"
            );
        }

        #[test]
        fn official_name_in_foreign_dir_is_rejected() {
            let daemon_dir = tempfile::tempdir().unwrap();
            let foreign = tempfile::tempdir().unwrap();
            let app = write_executable(foreign.path(), "super-stt-app", 0o755);
            assert!(
                !is_official_client_in(daemon_dir.path(), &app),
                "an official name outside the daemon dir must not be trusted"
            );
        }

        #[test]
        fn world_writable_official_binary_is_rejected() {
            let dir = tempfile::tempdir().unwrap();
            let app = write_executable(dir.path(), "super-stt-cli", 0o757);
            assert!(
                !is_official_client_in(dir.path(), &app),
                "a world-writable binary could be swapped by anyone"
            );
        }

        #[test]
        fn missing_exe_is_rejected() {
            let dir = tempfile::tempdir().unwrap();
            assert!(
                !is_official_client_in(dir.path(), &dir.path().join("super-stt-app")),
                "a nonexistent (e.g. replaced-on-disk) exe must fail closed"
            );
        }

        #[test]
        fn symlink_resolving_outside_daemon_dir_is_rejected() {
            let daemon_dir = tempfile::tempdir().unwrap();
            let foreign = tempfile::tempdir().unwrap();
            let target = write_executable(foreign.path(), "super-stt-cli", 0o755);
            let link = daemon_dir.path().join("super-stt-cli");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert!(
                !is_official_client_in(daemon_dir.path(), &link),
                "canonicalization must unmask a symlink escaping the daemon dir"
            );
        }

        /// Each daemon trusts its own clients and no other product's: a
        /// Super TTS daemon must not wave through `super-stt-app` just because
        /// it was installed in the same directory.
        #[test]
        fn another_products_client_is_not_official() {
            let dir = tempfile::tempdir().unwrap();
            let stt_app = write_executable(dir.path(), "super-stt-app", 0o755);
            let tts_app = write_executable(dir.path(), "super-tts-app", 0o755);
            assert!(in_dir(&SUPER_TTS, dir.path(), &tts_app));
            assert!(
                !in_dir(&SUPER_TTS, dir.path(), &stt_app),
                "a Super STT client must face Super TTS's consent dialog"
            );
        }
    }
}
