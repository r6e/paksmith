//! `KeyFlow` — pure state machine for the encrypted-pak key-entry flow.
//!
//! The machine starts `Idle`, moves to `Resolving` when an open is
//! initiated, transitions to `Locked` when the archive is encrypted but no
//! key was resolved, and to `Unlocked` once a valid key is supplied and the
//! open succeeds.

use std::path::{Path, PathBuf};

/// State machine for the key-entry flow.
///
/// All transitions are pure (no I/O). Async open tasks are coordinated
/// by `app.rs`; this type only tracks what the UI needs to render.
#[derive(Debug, Clone, Default)]
pub enum KeyFlow {
    /// No open in progress and no lock state active.
    #[default]
    Idle,
    /// An open attempt is in flight; key resolution is pending.
    Resolving,
    /// The archive at `path` is encrypted but no key could be resolved.
    /// `error` carries a human-readable message when a manual key attempt
    /// failed (bad hex parse or wrong key from core).
    Locked {
        /// Path to the encrypted archive.
        path: PathBuf,
        /// Error from the most recent failed key attempt, if any.
        error: Option<String>,
    },
    /// The archive was unlocked successfully.
    Unlocked,
}

impl KeyFlow {
    /// Transition to `Resolving`, recording `path` for later `lock`/`unlock`.
    ///
    /// Called when an open attempt starts so the UI can show a spinner or
    /// suppress interaction during resolution.
    pub fn begin(&mut self, _path: PathBuf) {
        *self = Self::Resolving;
    }

    /// Transition to `Locked { path, error: None }`.
    ///
    /// Called when the async open returns `OpenError::Locked`.
    pub fn lock(&mut self, path: PathBuf) {
        *self = Self::Locked { path, error: None };
    }

    /// Attach an error message to the `Locked` state (e.g. bad-hex or wrong
    /// key). No-op if not currently `Locked`.
    pub fn set_error(&mut self, msg: String) {
        if let Self::Locked { error, .. } = self {
            *error = Some(msg);
        }
    }

    /// Transition to `Unlocked`.
    pub fn unlock(&mut self) {
        *self = Self::Unlocked;
    }

    /// Return the locked path if in `Locked` state, `None` otherwise.
    pub fn is_locked(&self) -> Option<&Path> {
        if let Self::Locked { path, .. } = self {
            Some(path.as_path())
        } else {
            None
        }
    }

    /// Return the current error text, if any (only meaningful in `Locked`).
    pub fn error(&self) -> Option<&str> {
        if let Self::Locked { error: Some(e), .. } = self {
            Some(e.as_str())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn locks_then_unlocks() {
        let mut f = KeyFlow::Idle;
        f.begin(PathBuf::from("a.pak"));
        assert!(matches!(f, KeyFlow::Resolving));
        f.lock(PathBuf::from("a.pak"));
        assert!(f.is_locked().is_some());
        f.unlock();
        assert!(matches!(f, KeyFlow::Unlocked));
        assert!(f.is_locked().is_none());
    }

    #[test]
    fn lock_carries_path() {
        let mut f = KeyFlow::Idle;
        let path = PathBuf::from("/tmp/game.pak");
        f.lock(path.clone());
        assert_eq!(f.is_locked(), Some(path.as_path()));
    }

    #[test]
    fn error_field_settable_and_readable() {
        let mut f = KeyFlow::Idle;
        f.lock(PathBuf::from("x.pak"));
        assert!(f.error().is_none());
        f.set_error("bad hex".to_string());
        assert_eq!(f.error(), Some("bad hex"));
    }

    #[test]
    fn unlock_clears_is_locked() {
        let mut f = KeyFlow::Idle;
        f.lock(PathBuf::from("enc.pak"));
        assert!(f.is_locked().is_some());
        f.unlock();
        assert!(f.is_locked().is_none());
    }

    #[test]
    fn set_error_noop_when_not_locked() {
        let mut f = KeyFlow::Idle;
        f.set_error("ignored".to_string());
        // Still Idle, no panic
        assert!(f.is_locked().is_none());
    }
}
