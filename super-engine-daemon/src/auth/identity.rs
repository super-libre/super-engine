// SPDX-License-Identifier: GPL-3.0-only
//! Who the daemon believes is calling.

use crate::http::PeerInfo;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Who the daemon believes is calling.
///
/// The two variants are the two transports, and they are not the same kind of
/// claim. [`Self::Native`] is what the kernel says about a peer on the Unix
/// socket; [`Self::Web`] is what a browser says about the page it is running.
/// Keeping them as separate variants rather than one struct with optional
/// fields is what stops a check written for one from silently passing for the
/// other — `is_official_client` reading an absent exe path as "not official"
/// would be correct by accident, and one refactor away from not being.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PeerIdentity {
    /// A process on the Unix socket, identified by `SO_PEERCRED`.
    ///
    /// For an ordinary host process this is just the path the kernel says it
    /// is running — `/proc/<pid>/exe` on Linux, `proc_pidpath` on macOS. A peer
    /// inside a flatpak has its own mount namespace, so that path is resolved
    /// in *its* root and means nothing here: every such peer reads as something
    /// like `/app/bin/<name>`, a string any other sandbox can present just by
    /// naming its binary the same. Identifying a sandboxed caller by its exe
    /// path alone therefore hands one sandbox's grant to every other. The
    /// sandbox's own id is what distinguishes them, so it is carried alongside
    /// and is part of equality.
    ///
    /// The id is only as trustworthy as the sandbox that wrote it, and this is
    /// not a defence against a hostile process running as the user — one of
    /// those can read the session tokens out of the keyring regardless. It is
    /// what lets the daemon name the caller correctly in the consent dialog,
    /// and keep one sandboxed app's grant from silently covering another's.
    Native {
        /// The peer's executable path, as resolved in its own mount namespace
        /// on Linux (where a namespace is possible) — see [`peer_exe_path`].
        exe_path: PathBuf,
        /// `Some(app-id)` when the peer runs inside a flatpak sandbox.
        #[serde(default)]
        flatpak_app_id: Option<String>,
    },
    /// A page on the TCP listener, identified by its `Origin`.
    ///
    /// **This is a weaker claim than [`Self::Native`], and deliberately so.**
    /// The kernel vouches for an exe path; nothing vouches for an origin but
    /// the browser that sent it. A non-browser process can put any string here.
    /// What keeps that from mattering is that the daemon only accepts origins
    /// the user wrote into `[http.tcp].allowed_origins` — so forging one gets
    /// you no further than forging an origin the user already trusted, on a
    /// listener they already turned on.
    ///
    /// The consent dialog says which kind it is asking about, because "allow
    /// this website" and "allow this program" deserve different answers.
    Web {
        /// The full origin as the browser sent it: scheme, host and port.
        origin: String,
    },
}

impl PeerIdentity {
    /// A host process with no sandbox of its own.
    pub fn native(exe_path: impl Into<PathBuf>) -> Self {
        Self::Native {
            exe_path: exe_path.into(),
            flatpak_app_id: None,
        }
    }

    /// A browser page served from `origin`.
    pub fn web(origin: impl Into<String>) -> Self {
        Self::Web {
            origin: origin.into(),
        }
    }

    /// One line naming the caller, for logs and the consent dialog. A
    /// sandboxed peer leads with its app id, since its path is not a path
    /// anyone can go and look at; a web peer is named as a web peer, so a log
    /// line can never be read as naming a binary.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Native {
                exe_path,
                flatpak_app_id: Some(id),
            } => format!("flatpak {id} ({})", exe_path.display()),
            Self::Native { exe_path, .. } => exe_path.display().to_string(),
            Self::Web { origin } => format!("web origin {origin}"),
        }
    }
}

/// Which sandbox, if any, the peer is inside.
///
/// `/proc/<pid>/root` is the peer's root directory. When it is the same
/// directory as ours, the peer shares our view of the filesystem and its exe
/// path means what it says. When it differs, the peer has been pivoted
/// somewhere else and the path has to be read in *that* root, so we ask the
/// sandbox to name itself.
///
/// `Err(())` means the peer is in a root of its own that could not be
/// identified. Callers fail closed on it: an unidentifiable sandbox must not
/// be handed the identity its exe path would otherwise imply, which is
/// whatever host binary happens to sit at the same path.
///
/// Note that a namespace is not by itself a flatpak — a container would land
/// here too, and be refused for the same reason.
#[cfg(target_os = "linux")]
fn peer_sandbox_app_id(pid: u32, context: &str) -> Result<Option<String>, ()> {
    use std::os::unix::fs::MetadataExt as _;

    let root = format!("/proc/{pid}/root");
    let (Ok(peer_root), Ok(our_root)) = (std::fs::metadata(&root), std::fs::metadata("/")) else {
        log::warn!("{context}: cannot stat {root}; refusing to identify peer pid {pid}");
        return Err(());
    };
    if (peer_root.dev(), peer_root.ino()) == (our_root.dev(), our_root.ino()) {
        return Ok(None);
    }

    let info_path = format!("{root}/.flatpak-info");
    let Ok(info) = std::fs::read_to_string(&info_path) else {
        log::warn!(
            "{context}: peer pid {pid} runs in a mount namespace of its own but {info_path} is unreadable; cannot identify it"
        );
        return Err(());
    };
    let Some(app_id) = super_engine_protocol::sandbox::app_id_from_info(&info) else {
        log::warn!("{context}: {info_path} names no application; cannot identify peer pid {pid}");
        return Err(());
    };
    Ok(Some(app_id))
}

/// See the Linux [`peer_sandbox_app_id`]. Always `Ok(None)` on macOS.
///
/// Not a stub that gives something up. The Linux version exists because a
/// flatpak peer is pivoted into a root of its own, which makes its exe path
/// a claim about a filesystem this daemon cannot see. macOS has no such
/// pivot: the App Sandbox confines what a process may *open*, but leaves it
/// in the one system root, so `proc_pidpath` returns a path that means here
/// what it means there. There is no second namespace for an identity to be
/// ambiguous across, so there is nothing to disambiguate — and no
/// unidentifiable-sandbox case to fail closed on.
#[cfg(target_os = "macos")]
#[expect(
    clippy::unnecessary_wraps,
    reason = "signature is shared with the Linux arm, which genuinely fails"
)]
fn peer_sandbox_app_id(_pid: u32, _context: &str) -> Result<Option<String>, ()> {
    Ok(None)
}

/// The path of the binary running as `pid`, as the kernel reports it.
///
/// `/proc/<pid>/exe` is a kernel-maintained symlink to the executable the
/// process is running, which is what makes it an identity the daemon can
/// trust rather than something the peer told it.
///
/// `None` (logged with its reason) when the link cannot be read: Yama
/// `ptrace_scope`, systemd `ProtectProc=`, or the peer having exited and its
/// pid been recycled. Callers fail closed.
#[cfg(target_os = "linux")]
fn peer_exe_path(pid: u32, context: &str) -> Option<PathBuf> {
    let path = format!("/proc/{pid}/exe");
    match std::fs::read_link(&path) {
        Ok(p) => Some(p),
        Err(e) => {
            log::warn!("{context}: read_link({path}) failed: {e}; cannot identify peer pid {pid}");
            None
        }
    }
}

/// See the Linux [`peer_exe_path`]. macOS has no `/proc`, so the same fact
/// comes from `proc_pidpath`, which the kernel answers from the process's own
/// `p_textvp` — the vnode it was executed from. Same provenance as the Linux
/// symlink: the peer does not get a say in it.
///
/// `None` when `proc_pidpath` fails, which is the peer having exited (ESRCH)
/// or this daemon lacking the privilege to ask about it (EPERM — another
/// user's process, which the `SO_PEERCRED` uid check upstream already
/// refuses).
///
/// **One guarantee is weaker here than on Linux.** When a binary is replaced
/// on disk while running, Linux renders the link as `/path/to/exe (deleted)`,
/// so the daemon sees that the file behind a minted token is no longer the
/// one it approved. `proc_pidpath` reports only the path, and a path whose
/// file was swapped still resolves. A token stays bound to the path across
/// such a swap rather than being invalidated by it. The swap still requires
/// write access to the install directory — the same access needed to replace
/// the daemon itself — so it does not open a new door, but it does mean the
/// exe-change revocation is a Linux-only belt on top of that braces.
#[cfg(target_os = "macos")]
fn peer_exe_path(pid: u32, context: &str) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt as _;

    let Ok(pid) = i32::try_from(pid) else {
        log::warn!("{context}: peer pid {pid} does not fit in a pid_t; cannot identify it");
        return None;
    };
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: `buf` is a live allocation of exactly the length passed, and
    // `proc_pidpath` writes at most that many bytes into it.
    let written = unsafe {
        libc::proc_pidpath(
            pid,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            u32::try_from(buf.len()).unwrap_or(u32::MAX),
        )
    };
    if written <= 0 {
        let err = std::io::Error::last_os_error();
        log::warn!("{context}: proc_pidpath({pid}) failed: {err}; cannot identify peer pid {pid}");
        return None;
    }
    // `proc_pidpath` returns the byte length written, terminator excluded.
    // `written` is positive here — the `<= 0` branch above returned.
    let Ok(len) = usize::try_from(written) else {
        return None;
    };
    buf.truncate(len);
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(&buf)))
}

/// Resolve who is calling from the [`PeerInfo`] the accept loop attached.
/// Returns `None` when the peer can't be identified — a missing
/// `PeerInfo`/pid (`SO_PEERCRED` unsupported, peer process gone), a
/// kernel-denied executable lookup (Yama `ptrace_scope`, systemd
/// `ProtectProc=`, pid recycling — see [`peer_exe_path`]), or a sandbox that
/// would not name itself.
///
/// `context` names the caller in the log line, since both ends of a session's
/// life resolve the peer here: `auth_request` at mint time, and the
/// per-request authorization check on every call after it.
///
/// A peer that arrived over TCP has no kernel-attested identity at all, so it
/// is resolved from its `Origin` instead — see [`PeerInfo::web_origin`]. That
/// field is only ever set by the origin gate, which has already checked the
/// value against the user's allowlist; nothing here re-derives it from a
/// header, so there is exactly one place an origin can enter the system.
///
/// The caller **must fail closed** on `None`: the consent model verifies a
/// *binary*, so an unidentifiable peer must not be prompted for (a
/// `<unknown>`-labelled dialog is meaningless to approve) nor minted a token
/// bound to a bogus identity that the `/events` exe-watch would then spuriously
/// revoke (audit 2 Tier 3 #9). Each failure is logged with its specific reason.
#[must_use]
pub fn resolve_peer_identity(peer: Option<&PeerInfo>, context: &str) -> Option<PeerIdentity> {
    let Some(peer) = peer else {
        log::warn!(
            "{context}: no PeerInfo extension attached — cannot identify the requesting binary"
        );
        return None;
    };
    if let Some(origin) = &peer.web_origin {
        return Some(PeerIdentity::Web {
            origin: origin.clone(),
        });
    }
    let Some(pid) = peer.pid else {
        log::warn!(
            "{context}: PeerInfo had no pid (SO_PEERCRED returned no credentials); cannot resolve exe"
        );
        return None;
    };
    let exe_path = peer_exe_path(pid, context)?;
    let flatpak_app_id = peer_sandbox_app_id(pid, context).ok()?;

    Some(PeerIdentity::Native {
        exe_path,
        flatpak_app_id,
    })
}
