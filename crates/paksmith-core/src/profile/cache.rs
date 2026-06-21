//! On-disk registry cache: `<config_dir>/paksmith/registry-cache.json`, 0600.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::PaksmithError;
use crate::error::ProfileFault;
use crate::profile::registry::{MAX_BODY_BYTES, RegistryDoc, RegistryProfile, validate_caps};
use crate::profile::store::{config_base_dir, write_restricted};

/// Cached registry document + the wall-clock fetch time.
#[derive(Debug, Clone)]
pub struct RegistryCache {
    /// Unix seconds when fetched.
    pub fetched_at_unix: u64,
    /// The cached document.
    pub doc: RegistryDoc,
}

// On-disk shape. `profiles` reuses RegistryProfile's serde directly;
// validate_caps is re-applied on load to enforce caps against untrusted
// user-editable on-disk content.
#[derive(Serialize, Deserialize)]
struct OnDisk {
    fetched_at_unix: u64,
    profiles: Vec<RegistryProfile>,
}

impl RegistryCache {
    /// `<config_dir>/paksmith/registry-cache.json`.
    pub fn path() -> Result<PathBuf, PaksmithError> {
        Ok(config_base_dir()?.join("registry-cache.json"))
    }

    /// Load from the resolved path. Returns `Ok(None)` if the file is absent.
    pub fn load() -> Result<Option<Self>, PaksmithError> {
        Self::load_from(&Self::path()?)
    }

    /// Save to the resolved path at `0600`.
    pub fn save(&self) -> Result<(), PaksmithError> {
        self.save_to(&Self::path()?)
    }

    /// Load from an explicit path. Returns `Ok(None)` if the file is absent.
    ///
    /// Re-applies `validate_caps` to the untrusted on-disk content so a
    /// hand-edited cache cannot exceed the registry caps.
    pub(crate) fn load_from(path: &Path) -> Result<Option<Self>, PaksmithError> {
        // Cap the read against MAX_BODY_BYTES before pulling the file into memory:
        // the cache is user-editable, so a hand-grown multi-GiB file must not OOM
        // us. The size check is advisory — when `metadata` succeeds and reports a
        // size over the cap we reject early; any metadata error is left for the
        // authoritative `fs::read` below, which performs the NotFound (→ Ok(None))
        // vs Io discrimination exactly as before.
        if let Ok(meta) = std::fs::metadata(path)
            && meta.len() > MAX_BODY_BYTES as u64
        {
            return Err(PaksmithError::Profile {
                fault: ProfileFault::CacheCorrupt {
                    reason: format!("cache file exceeds {MAX_BODY_BYTES} bytes"),
                },
            });
        }
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(PaksmithError::Profile {
                    fault: ProfileFault::Io {
                        reason: e.to_string(),
                    },
                });
            }
        };
        let on_disk: OnDisk =
            serde_json::from_slice(&bytes).map_err(|e| PaksmithError::Profile {
                fault: ProfileFault::CacheCorrupt {
                    reason: e.to_string(),
                },
            })?;
        // Re-validate caps: the cache file is user-editable — trust nothing.
        let doc = validate_caps(RegistryDoc {
            profiles: on_disk.profiles,
        })
        .map_err(|reason| PaksmithError::Profile {
            fault: ProfileFault::CacheCorrupt { reason },
        })?;
        Ok(Some(Self {
            fetched_at_unix: on_disk.fetched_at_unix,
            doc,
        }))
    }

    /// Save to an explicit path. Creates parent dirs, writes atomically via a
    /// sibling `.tmp` file renamed into place. The file is born `0600` on unix
    /// (no world-readable window) — the cache holds AES key material.
    pub(crate) fn save_to(&self, path: &Path) -> Result<(), PaksmithError> {
        let io_err = |e: std::io::Error| PaksmithError::Profile {
            fault: ProfileFault::Io {
                reason: e.to_string(),
            },
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(io_err)?;
        }
        let on_disk = OnDisk {
            fetched_at_unix: self.fetched_at_unix,
            profiles: self.doc.profiles.clone(),
        };
        let json = serde_json::to_vec_pretty(&on_disk).map_err(|e| PaksmithError::Profile {
            fault: ProfileFault::Io {
                reason: e.to_string(),
            },
        })?;
        let tmp = path.with_extension("json.tmp");
        write_restricted(&tmp, &json).map_err(io_err)?;
        std::fs::rename(&tmp, path).map_err(io_err)?;
        Ok(())
    }

    /// True iff `now_unix` is more than `staleness_hours` after the fetch time.
    ///
    /// Pure — the caller injects `now_unix` so there is no `SystemTime` call
    /// inside (no hidden I/O; trivially testable).
    pub fn is_stale(&self, now_unix: u64, staleness_hours: u64) -> bool {
        now_unix.saturating_sub(self.fetched_at_unix) > staleness_hours.saturating_mul(3600)
    }

    /// Look up a cached profile by id. `O(n)` — profile counts are small.
    pub fn get(&self, id: &str) -> Option<&RegistryProfile> {
        self.doc.profiles.iter().find(|p| p.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::registry::{RegistryDoc, RegistryProfile};
    use std::collections::BTreeMap;

    fn sample() -> RegistryCache {
        RegistryCache {
            fetched_at_unix: 1_000_000,
            doc: RegistryDoc {
                profiles: vec![RegistryProfile {
                    id: "g".into(),
                    name: "G".into(),
                    engine_version: None,
                    keys: BTreeMap::new(),
                }],
            },
        }
    }

    #[test]
    fn save_then_load_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry-cache.json");
        sample().save_to(&path).unwrap();
        let back = RegistryCache::load_from(&path).unwrap().unwrap();
        assert_eq!(back.fetched_at_unix, 1_000_000);
        assert_eq!(back.get("g").unwrap().name, "G");
    }

    #[test]
    fn load_missing_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            RegistryCache::load_from(&dir.path().join("nope.json"))
                .unwrap()
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn saved_cache_is_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry-cache.json");
        sample().save_to(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn corrupt_is_typed_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry-cache.json");
        std::fs::write(&path, "not json {{{").unwrap();
        assert!(matches!(
            RegistryCache::load_from(&path).unwrap_err(),
            crate::PaksmithError::Profile {
                fault: crate::error::ProfileFault::CacheCorrupt { .. }
            }
        ));
    }

    #[test]
    fn staleness_boundary() {
        let c = sample(); // fetched_at = 1_000_000
        // 24h = 86_400s. +86_399 → fresh; +86_400 (exact) → fresh (strict `>`);
        // +86_401 → stale. The exact-boundary case pins `>` vs `>=`.
        assert!(!c.is_stale(1_000_000 + 86_399, 24));
        assert!(
            !c.is_stale(1_000_000 + 86_400, 24),
            "exactly at threshold is still fresh"
        );
        assert!(c.is_stale(1_000_000 + 86_401, 24));
    }

    /// `load_from` on an existing *directory* path (EISDIR, not NotFound) must
    /// return an `Io` error, not `Ok(None)`. Pins the `NotFound` match guard so
    /// replacing it with `true` (treating ALL errors as "file absent") is caught.
    #[test]
    fn load_from_directory_is_typed_io_error() {
        let dir = tempfile::tempdir().unwrap();
        // Pass the directory itself — `fs::read` will fail with EISDIR (not NotFound).
        let err = RegistryCache::load_from(dir.path()).unwrap_err();
        assert!(
            matches!(
                err,
                crate::PaksmithError::Profile {
                    fault: crate::error::ProfileFault::Io { .. }
                }
            ),
            "reading a directory must produce an Io fault, not Ok(None): {err}"
        );
    }

    /// A cache file larger than `MAX_BODY_BYTES` must be rejected by the size
    /// check before being read into memory — a typed `CacheCorrupt` carrying the
    /// "exceeds" reason, never an OOM. Asserts the *reason* (not just the variant)
    /// so the size path is distinguished from the parse-failure path: a sparse
    /// zero-byte file also fails serde_json, so matching only `CacheCorrupt`
    /// would let `> → ==`/`<` mutants survive. Uses sparse `set_len` (no 8 MiB write).
    #[test]
    fn oversized_cache_file_is_rejected_by_size_check() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry-cache.json");
        let f = std::fs::File::create(&path).unwrap();
        f.set_len(MAX_BODY_BYTES as u64 + 1).unwrap();
        drop(f);
        let err = RegistryCache::load_from(&path).unwrap_err();
        let crate::PaksmithError::Profile {
            fault: crate::error::ProfileFault::CacheCorrupt { reason },
        } = err
        else {
            panic!("oversized cache must produce CacheCorrupt, not OOM: {err}");
        };
        assert!(
            reason.contains("exceeds"),
            "cap+1 must trip the size check (reason mentions 'exceeds'), not the parse path: {reason}"
        );
    }

    /// A file of EXACTLY `MAX_BODY_BYTES` must NOT trip the size check (strict
    /// `>`): it falls through to read + parse. A sparse all-zero file of that
    /// size still fails serde_json → `CacheCorrupt`, but the reason must NOT be
    /// the "exceeds" size-cap string. Pins `> → >=` (a `>=` mutant would reject
    /// the boundary with the "exceeds" reason here).
    #[test]
    fn cache_file_exactly_at_cap_is_not_size_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry-cache.json");
        let f = std::fs::File::create(&path).unwrap();
        f.set_len(MAX_BODY_BYTES as u64).unwrap();
        drop(f);
        let err = RegistryCache::load_from(&path).unwrap_err();
        let crate::PaksmithError::Profile {
            fault: crate::error::ProfileFault::CacheCorrupt { reason },
        } = err
        else {
            panic!("exactly-cap all-zero file must still parse-fail to CacheCorrupt: {err}");
        };
        assert!(
            !reason.contains("exceeds"),
            "exactly MAX_BODY_BYTES must fall through the strict `>` check, not be size-rejected: {reason}"
        );
    }

    #[test]
    fn load_re_applies_caps_to_untrusted_file() {
        // A hand-edited cache that parses as valid JSON but violates a cap
        // (overlong id > MAX_STR) must be rejected on load — the cache file is
        // untrusted, so `load_from` re-runs validate_caps.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry-cache.json");
        let overlong_id = "a".repeat(crate::profile::registry::MAX_STR + 1);
        let json = format!(
            r#"{{"fetched_at_unix":1,"profiles":[{{"id":"{overlong_id}","name":"y","keys":{{}}}}]}}"#
        );
        std::fs::write(&path, json).unwrap();
        assert!(matches!(
            RegistryCache::load_from(&path).unwrap_err(),
            crate::PaksmithError::Profile {
                fault: crate::error::ProfileFault::CacheCorrupt { .. }
            }
        ));
    }
}
