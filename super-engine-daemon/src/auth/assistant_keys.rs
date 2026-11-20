// SPDX-License-Identifier: GPL-3.0-only
//! Assistant keys: what an AI assistant presents to call the daemon over its
//! loopback TCP listener.
//!
//! An assistant is neither of the callers the rest of the auth model knows. It
//! is not a binary on the Unix socket that the kernel can name, and it is not a
//! page whose origin the user put on the allowlist: it is a program that sends
//! `Authorization: Bearer <key>` and no `Origin` at all. So it does not ask for
//! a session through the consent dialog. The user connects it by hand, in the
//! product's settings, and the product asks the daemon to mint it a key.
//!
//! The key is the assistant's whole identity. It never expires, and it stops
//! working only when the user revokes it. Each key has a short id, which is
//! not secret: lists, logs and the rate limiter name a key by its id, and the
//! secret itself is only handed out by the product, to the assistant it was
//! minted for.
//!
//! The keys are kept in the [secrets file](crate::secrets), in a field of their
//! own beside the session tokens rather than as a kind of session. A daemon
//! from before assistant keys skips a field it does not know, but it cannot
//! read a session whose grantee is a kind it does not know, and a file it
//! cannot read is one it sets aside, backend API keys and all.

use crate::auth::identity::PeerIdentity;
use crate::auth::tokens::TokenMeta;
use crate::secrets::{Secrets, SecretsError};
use chrono::{DateTime, Utc};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// What every assistant key starts with.
///
/// It tells an assistant key from a session token at a glance, and lets
/// [`TokenStore::validate`](crate::auth::tokens::TokenStore::validate) look a
/// bearer up in the right place. A session token is lowercase hex and never
/// contains `_`, so the two can never be confused.
pub const PREFIX: &str = "sva_";

/// How many random bytes are in a key's secret. Hex-encoded after
/// [`PREFIX`], as 64 characters.
const SECRET_BYTES: usize = 32;

/// How many random bytes are in a key's id. Hex-encoded, as 8 characters. The
/// id only has to be unique among this daemon's keys, and minting checks that
/// it is.
const ID_BYTES: usize = 4;

/// One assistant key, without its secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssistantKey {
    /// A short hex id that names the key. Not a secret.
    pub id: String,
    /// The name the product gave the assistant, such as `Claude Code`.
    pub name: String,
    /// The scopes the key grants, sorted and deduplicated.
    pub scopes: Vec<String>,
    /// When the key was minted.
    pub created_at: DateTime<Utc>,
}

impl AssistantKey {
    /// The key as the session a guard checks.
    ///
    /// Shaped like a session token's metadata so the guards and handlers
    /// downstream treat an assistant like any other caller. The grantee is the
    /// key's own identity, which only
    /// [`require_assistant_caller`](crate::auth::middleware::require_assistant_caller)
    /// gives a request. It never expires, so its expiry is the last second
    /// RFC 3339 can write with a four-digit year.
    pub(crate) fn token_meta(&self) -> TokenMeta {
        TokenMeta {
            app_name: self.name.clone(),
            scopes: self.scopes.clone(),
            grantee: PeerIdentity::Assistant {
                key_id: self.id.clone(),
            },
            issued_at: self.created_at,
            expires_at: never(),
        }
    }
}

/// The expiry of a key that never expires: 9999-12-31T23:59:59Z.
fn never() -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(253_402_300_799, 0).unwrap_or(DateTime::<Utc>::MAX_UTC)
}

/// The assistant keys a daemon has minted, by secret, and their copy in the
/// secrets file. Cheap to clone; clones share one map.
#[derive(Clone)]
pub(crate) struct AssistantKeyStore {
    /// The keys, by secret. The hot path: every request on an assistant route
    /// looks its bearer up here.
    keys: Arc<Mutex<BTreeMap<String, AssistantKey>>>,
    /// Held across a whole mint or revoke, file write included, so two of
    /// them at once cannot each write a map that lacks the other's change.
    writes: Arc<tokio::sync::Mutex<()>>,
    secrets: Secrets,
}

impl AssistantKeyStore {
    /// The keys persisted in `secrets`.
    pub(crate) fn load(secrets: Secrets) -> Self {
        let keys = secrets.assistant_keys();
        if !keys.is_empty() {
            log::info!("Loaded {} assistant keys", keys.len());
        }
        Self {
            keys: Arc::new(Mutex::new(keys)),
            writes: Arc::new(tokio::sync::Mutex::new(())),
            secrets,
        }
    }

    /// Mint a key for the assistant `name`, granting `scopes`, and write it to
    /// the secrets file before handing it out.
    pub(crate) async fn mint(
        &self,
        name: &str,
        scopes: &[String],
    ) -> Result<(String, AssistantKey), SecretsError> {
        let _write = self.writes.lock().await;
        let mut next = self.keys.lock().unwrap().clone();
        let id = loop {
            let id = random_hex(ID_BYTES);
            if !next.values().any(|key| key.id == id) {
                break id;
            }
        };
        let secret = format!("{PREFIX}{}", random_hex(SECRET_BYTES));
        let mut scopes = scopes.to_vec();
        scopes.sort();
        scopes.dedup();
        let key = AssistantKey {
            id,
            name: name.to_string(),
            scopes,
            created_at: Utc::now(),
        };
        next.insert(secret.clone(), key.clone());
        self.persist(next.clone()).await?;
        *self.keys.lock().unwrap() = next;
        log::info!(
            "Minted assistant key {} for {} (scopes: {})",
            key.id,
            key.name,
            key.scopes.join(" ")
        );
        Ok((secret, key))
    }

    /// Every key, oldest first, without its secret.
    pub(crate) fn list(&self) -> Vec<AssistantKey> {
        let mut keys: Vec<AssistantKey> = self.keys.lock().unwrap().values().cloned().collect();
        keys.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
        keys
    }

    /// The secret of the key `id`, or `None` when there is no such key.
    pub(crate) fn secret(&self, id: &str) -> Option<String> {
        self.keys
            .lock()
            .unwrap()
            .iter()
            .find(|(_, key)| key.id == id)
            .map(|(secret, _)| secret.clone())
    }

    /// The key whose secret is `secret`.
    pub(crate) fn lookup(&self, secret: &str) -> Option<AssistantKey> {
        self.keys.lock().unwrap().get(secret).cloned()
    }

    /// Revoke the key `id` and write the change. `false` when there was no
    /// such key, which is already revoked.
    pub(crate) async fn revoke(&self, id: &str) -> Result<bool, SecretsError> {
        let _write = self.writes.lock().await;
        let mut next = self.keys.lock().unwrap().clone();
        let before = next.len();
        next.retain(|_, key| key.id != id);
        if next.len() == before {
            return Ok(false);
        }
        self.persist(next.clone()).await?;
        *self.keys.lock().unwrap() = next;
        log::info!("Revoked assistant key {id}");
        Ok(true)
    }

    /// Write `keys` to the secrets file on a blocking thread.
    async fn persist(&self, keys: BTreeMap<String, AssistantKey>) -> Result<(), SecretsError> {
        let secrets = self.secrets.clone();
        tokio::task::spawn_blocking(move || secrets.set_assistant_keys(keys))
            .await
            .map_err(|e| SecretsError::Task(e.to_string()))?
    }
}

/// `bytes` bytes from the system's secure random source, as lowercase hex.
fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    SystemRandom::new()
        .fill(&mut buf)
        .expect("SystemRandom::fill");
    hex::encode(buf)
}

#[cfg(test)]
mod tests {
    use super::{AssistantKeyStore, PREFIX};
    use crate::auth::identity::PeerIdentity;
    use crate::auth::tokens::TokenStore;
    use crate::secrets::{FILE_NAME, Secrets};

    fn scopes(names: &[&str]) -> Vec<String> {
        names.iter().map(ToString::to_string).collect()
    }

    /// A minted key validates as a session whose grantee is the key itself,
    /// with the scopes it was minted with, and it does not expire.
    #[tokio::test]
    async fn a_minted_key_validates_as_its_own_assistant() {
        let store = TokenStore::default();
        let (secret, key) = store
            .mint_assistant_key("Claude Code", &scopes(&["tts", "stt", "tts"]))
            .await
            .expect("mint");

        assert!(secret.starts_with(PREFIX), "{secret}");
        let hex = &secret[PREFIX.len()..];
        assert_eq!(hex.len(), 64, "{secret}");
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "the secret is lowercase hex after the prefix: {secret}"
        );
        assert_eq!(key.id.len(), 8, "{key:?}");
        assert_eq!(key.scopes, scopes(&["stt", "tts"]), "sorted, deduplicated");

        let meta = store.validate(&secret).expect("a minted key validates");
        assert_eq!(meta.app_name, "Claude Code");
        assert_eq!(meta.scopes, key.scopes);
        assert_eq!(
            meta.grantee,
            PeerIdentity::Assistant {
                key_id: key.id.clone()
            }
        );
        assert_eq!(meta.issued_at, key.created_at);
        assert_eq!(meta.expires_at.to_rfc3339(), "9999-12-31T23:59:59+00:00");
    }

    /// A bearer with the prefix that names no key is unknown, the same answer
    /// as for a session token that was never minted.
    #[test]
    fn an_unknown_key_is_unknown() {
        let store = TokenStore::default();
        assert!(matches!(
            store.validate(&format!("{PREFIX}{}", "0".repeat(64))),
            Err("unknown")
        ));
    }

    /// The list names every key without its secret, and the secret can be read
    /// back by id for the product to hand to its assistant.
    #[tokio::test]
    async fn the_list_hides_secrets_and_the_secret_reads_back_by_id() {
        let store = TokenStore::default();
        let (first_secret, first) = store
            .mint_assistant_key("Claude Code", &scopes(&["tts"]))
            .await
            .unwrap();
        let (second_secret, second) = store
            .mint_assistant_key("Codex", &scopes(&["stt"]))
            .await
            .unwrap();
        assert_ne!(first.id, second.id);
        assert_ne!(first_secret, second_secret);

        let listed = store.assistant_keys();
        assert_eq!(listed, vec![first.clone(), second.clone()], "oldest first");
        let shown = format!("{listed:?}");
        assert!(!shown.contains(&first_secret[PREFIX.len()..]), "{shown}");
        assert!(!shown.contains(&second_secret[PREFIX.len()..]), "{shown}");

        assert_eq!(
            store.assistant_key_secret(&first.id).as_deref(),
            Some(first_secret.as_str())
        );
        assert_eq!(
            store.assistant_key_secret(&second.id).as_deref(),
            Some(second_secret.as_str())
        );
        assert_eq!(store.assistant_key_secret("00000000"), None);
    }

    /// A revoked key stops working at once, and the others keep working.
    #[tokio::test]
    async fn a_revoked_key_is_unknown() {
        let store = TokenStore::default();
        let (gone_secret, gone) = store
            .mint_assistant_key("Claude Code", &scopes(&["tts"]))
            .await
            .unwrap();
        let (kept_secret, _) = store
            .mint_assistant_key("Codex", &scopes(&["tts"]))
            .await
            .unwrap();

        assert!(store.revoke_assistant_key(&gone.id).await.unwrap());
        assert!(matches!(store.validate(&gone_secret), Err("unknown")));
        assert_eq!(store.assistant_key_secret(&gone.id), None);
        assert!(store.validate(&kept_secret).is_ok());
        assert!(
            !store.revoke_assistant_key(&gone.id).await.unwrap(),
            "revoking twice finds nothing the second time"
        );
    }

    /// Keys are in the file before the mint returns, and the next daemon reads
    /// them back; a revoke is in the file too.
    #[tokio::test]
    async fn keys_survive_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);

        let store = AssistantKeyStore::load(Secrets::at(path.clone()).unwrap());
        let (secret, key) = store.mint("Claude Code", &scopes(&["tts"])).await.unwrap();
        let (revoked, revoked_key) = store.mint("Codex", &scopes(&["stt"])).await.unwrap();
        assert!(store.revoke(&revoked_key.id).await.unwrap());

        let next = AssistantKeyStore::load(Secrets::at(path).unwrap());
        assert_eq!(next.lookup(&secret), Some(key.clone()));
        assert_eq!(next.list(), vec![key]);
        assert_eq!(next.lookup(&revoked), None);
    }

    /// A key that could not be written is not handed out: the caller would
    /// give the assistant a key the next daemon has never heard of.
    #[tokio::test]
    async fn a_key_that_cannot_be_written_is_not_minted() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let store = AssistantKeyStore::load(Secrets::at(state.join(FILE_NAME)).unwrap());
        // A file takes the directory's place, so the secrets file cannot be
        // created.
        std::fs::write(&state, b"").unwrap();

        assert!(store.mint("Claude Code", &scopes(&["tts"])).await.is_err());
        assert!(store.list().is_empty());
    }
}
