//! `paksmith profile` subcommand — add / list / show / remove profiles,
//! plus key management (`key add` / `key remove`) and key testing (`test`).

use std::collections::BTreeMap;

use clap::{Args, Subcommand};

use paksmith_core::error::ProfileFault;
use paksmith_core::{AesKey, GameProfile, KeyGuid, PaksmithError, ProfileStore, display_guid};

use crate::output::OutputFormat;

/// Profile management subcommands.
#[derive(Subcommand)]
pub(crate) enum ProfileCmd {
    /// Create a new profile
    Add(AddArgs),
    /// List stored profiles
    List,
    /// Show one profile
    Show(ShowArgs),
    /// Delete a profile
    Remove(RemoveArgs),
    /// Manage AES keys for a profile
    Key {
        #[command(subcommand)]
        cmd: KeyCmd,
    },
    /// Test the profile's resolved key against a pak
    Test(TestArgs),
    /// Fetch and cache the remote profile registry
    Fetch(FetchArgs),
    /// List all profiles whose detection rules match a game install directory
    Detect(DetectArgs),
}

/// Arguments for `profile detect`.
#[derive(Args)]
pub(crate) struct DetectArgs {
    /// Game install directory to probe.
    pub(crate) dir: std::path::PathBuf,
}

/// Arguments for `profile fetch`.
#[derive(Args)]
pub(crate) struct FetchArgs {
    /// Override the configured registry URL for this fetch.
    #[arg(long)]
    pub(crate) registry: Option<String>,
    /// Fetch even if the cache is still fresh.
    #[arg(long)]
    pub(crate) force: bool,
}

/// Key management subcommands.
#[derive(Subcommand)]
pub(crate) enum KeyCmd {
    /// Add (or replace) a key for a GUID
    Add(KeyAddArgs),
    /// Remove a key by GUID
    Remove(KeyRemoveArgs),
}

#[derive(Args)]
pub(crate) struct KeyAddArgs {
    /// Profile id
    pub(crate) id: String,
    /// AES-256 key, 64 hex chars (optional 0x prefix)
    #[arg(long)]
    pub(crate) key: String,
    /// Encryption-key GUID, 32 hex chars. Defaults to the all-zero default.
    #[arg(long)]
    pub(crate) guid: Option<String>,
}

#[derive(Args)]
pub(crate) struct KeyRemoveArgs {
    /// Profile id
    pub(crate) id: String,
    /// Encryption-key GUID, 32 hex chars
    #[arg(long)]
    pub(crate) guid: String,
}

#[derive(Args)]
pub(crate) struct TestArgs {
    /// Profile id
    pub(crate) id: String,
    /// Pak to test the resolved key against
    pub(crate) pak: std::path::PathBuf,
}

#[derive(Args)]
pub(crate) struct AddArgs {
    /// Profile id (used by `--game`)
    pub(crate) id: String,
    /// Display name
    #[arg(long)]
    pub(crate) name: String,
    /// Engine version, e.g. 5.3
    #[arg(long)]
    pub(crate) engine_version: Option<String>,
}

#[derive(Args)]
pub(crate) struct ShowArgs {
    /// Profile id
    pub(crate) id: String,
    /// Reveal key hex (default: redacted)
    #[arg(long)]
    pub(crate) show_keys: bool,
}

#[derive(Args)]
pub(crate) struct RemoveArgs {
    /// Profile id
    pub(crate) id: String,
}

/// Dispatch a [`ProfileCmd`] and return a process exit code byte.
///
/// `_format` is accepted for CLI consistency but ignored: `profile` output is
/// human-readable only. Structured (`--format json`) output is deferred to a
/// later sub-phase.
pub(crate) fn run(cmd: &ProfileCmd, _format: OutputFormat) -> paksmith_core::Result<u8> {
    match cmd {
        ProfileCmd::Add(a) => add(a),
        ProfileCmd::List => list(),
        ProfileCmd::Show(a) => show(a),
        ProfileCmd::Remove(a) => remove(a),
        ProfileCmd::Key { cmd } => match cmd {
            KeyCmd::Add(a) => key_add(a),
            KeyCmd::Remove(a) => key_remove(a),
        },
        ProfileCmd::Test(a) => test(a),
        ProfileCmd::Fetch(a) => fetch(a),
        ProfileCmd::Detect(a) => crate::commands::detect::run(&a.dir),
    }
}

fn add(a: &AddArgs) -> paksmith_core::Result<u8> {
    let mut store = ProfileStore::load()?;
    if store.profiles.contains_key(&a.id) {
        return Err(PaksmithError::InvalidArgument {
            arg: "id",
            reason: format!("profile `{}` already exists", a.id),
        });
    }
    let _ = store.profiles.insert(
        a.id.clone(),
        GameProfile {
            name: a.name.clone(),
            engine_version: a.engine_version.clone(),
            keys: BTreeMap::new(),
            detect: None,
        },
    );
    store.save()?;
    println!("added profile `{}`", a.id);
    Ok(0)
}

fn list() -> paksmith_core::Result<u8> {
    let store = ProfileStore::load()?;
    let cache = paksmith_core::profile::resolve::load_cache_lenient();

    let mut any = false;

    // Local profiles first (always win over cache entries with the same id).
    for (id, p) in &store.profiles {
        let engine = p.engine_version.as_deref().unwrap_or("-");
        println!(
            "{id}\t{}\t{engine}\t{} key(s)\t[local]",
            p.name,
            p.keys.len()
        );
        any = true;
    }

    // Registry-only entries: skip any id that already appeared locally.
    if let Some(c) = &cache {
        for p in &c.doc.profiles {
            if store.profiles.contains_key(&p.id) {
                continue;
            }
            let engine = p.engine_version.as_deref().unwrap_or("-");
            println!(
                "{}\t{}\t{engine}\t{} key(s)\t[registry]",
                p.id,
                p.name,
                p.keys.len()
            );
            any = true;
        }
    }

    if !any {
        println!("no profiles");
    }
    Ok(0)
}

fn show(a: &ShowArgs) -> paksmith_core::Result<u8> {
    let store = ProfileStore::load()?;
    let p = store
        .profiles
        .get(&a.id)
        .ok_or_else(|| PaksmithError::Profile {
            fault: ProfileFault::ProfileNotFound { id: a.id.clone() },
        })?;
    println!("id: {}", a.id);
    println!("name: {}", p.name);
    println!(
        "engine_version: {}",
        p.engine_version.as_deref().unwrap_or("-")
    );
    println!("keys:");
    for (guid, key) in &p.keys {
        if a.show_keys {
            // Deliberate reveal: only `--show-keys` renders key material.
            println!(
                "  {} = {}",
                guid.to_hex(),
                paksmith_core::profile::key_hex(key)
            );
        } else {
            println!("  {} = <redacted>", guid.to_hex());
        }
    }
    Ok(0)
}

fn remove(a: &RemoveArgs) -> paksmith_core::Result<u8> {
    let mut store = ProfileStore::load()?;
    if store.profiles.remove(&a.id).is_none() {
        return Err(PaksmithError::Profile {
            fault: ProfileFault::ProfileNotFound { id: a.id.clone() },
        });
    }
    store.save()?;
    println!("removed profile `{}`", a.id);
    Ok(0)
}

fn key_add(a: &KeyAddArgs) -> paksmith_core::Result<u8> {
    let key = AesKey::from_hex(&a.key).map_err(|e| PaksmithError::InvalidArgument {
        arg: "--key",
        reason: e.to_string(),
    })?;
    let guid = match &a.guid {
        Some(g) => KeyGuid::from_hex(g).map_err(|e| PaksmithError::InvalidArgument {
            arg: "--guid",
            reason: e.to_string(),
        })?,
        None => KeyGuid::ZERO,
    };
    let mut store = ProfileStore::load()?;
    let p = store
        .profiles
        .get_mut(&a.id)
        .ok_or_else(|| PaksmithError::Profile {
            fault: ProfileFault::ProfileNotFound { id: a.id.clone() },
        })?;
    let _ = p.keys.insert(guid, key);
    store.save()?;
    println!("added key for GUID {} to `{}`", guid.to_hex(), a.id);
    Ok(0)
}

fn key_remove(a: &KeyRemoveArgs) -> paksmith_core::Result<u8> {
    let guid = KeyGuid::from_hex(&a.guid).map_err(|e| PaksmithError::InvalidArgument {
        arg: "--guid",
        reason: e.to_string(),
    })?;
    let mut store = ProfileStore::load()?;
    let p = store
        .profiles
        .get_mut(&a.id)
        .ok_or_else(|| PaksmithError::Profile {
            fault: ProfileFault::ProfileNotFound { id: a.id.clone() },
        })?;
    if p.keys.remove(&guid).is_none() {
        return Err(PaksmithError::Profile {
            fault: ProfileFault::NoKeyForGuid {
                id: a.id.clone(),
                guid: guid.to_hex(),
            },
        });
    }
    store.save()?;
    println!("removed key for GUID {} from `{}`", guid.to_hex(), a.id);
    Ok(0)
}

fn fetch(a: &FetchArgs) -> paksmith_core::Result<u8> {
    use paksmith_core::RegistryConfig;
    use paksmith_core::profile::cache::RegistryCache;
    use paksmith_core::profile::registry::RegistryClient;

    let cfg = RegistryConfig::load()?;
    // Destructure before any field is moved so the borrow checker sees all
    // fields simultaneously available.
    let RegistryConfig {
        url: cfg_url,
        staleness_hours,
        public_key_hex,
    } = cfg;
    let url = a.registry.as_deref().unwrap_or(&cfg_url).to_owned();

    let now = paksmith_core::profile::resolve::now_unix()?;

    // A corrupt/unreadable cache degrades to `None` (warn) so `profile fetch`
    // proceeds to fetch a fresh copy — it overwrites the cache anyway, so a
    // bad existing file must never block the recovery path.
    if !a.force
        && let Some(existing) = paksmith_core::profile::resolve::load_cache_lenient()
        && !existing.is_stale(now, staleness_hours)
    {
        println!(
            "registry cache is fresh ({} profiles); use --force to re-fetch",
            existing.doc.profiles.len()
        );
        return Ok(0);
    }

    paksmith_core::profile::config::ensure_key_matches_registry(&url, &public_key_hex)?;
    let client = RegistryClient::new()?;
    let doc = crate::block_on(client.fetch(&url, &public_key_hex))?;
    let cache = RegistryCache {
        fetched_at_unix: now,
        doc,
    };
    cache.save()?;
    println!("fetched {} profiles", cache.doc.profiles.len());
    Ok(0)
}

fn test(a: &TestArgs) -> paksmith_core::Result<u8> {
    use paksmith_core::container::pak::PakReader;
    use paksmith_core::profile::key_test::{KeyTestOutcome, test_key};
    use paksmith_core::profile::resolve_key;

    let store = ProfileStore::load()?;
    let p = store
        .profiles
        .get(&a.id)
        .ok_or_else(|| PaksmithError::Profile {
            fault: ProfileFault::ProfileNotFound { id: a.id.clone() },
        })?;
    let guid = PakReader::read_footer_guid(&a.pak)?;
    let key = resolve_key(p, guid.as_ref()).ok_or_else(|| PaksmithError::Profile {
        fault: ProfileFault::NoKeyForGuid {
            id: a.id.clone(),
            guid: display_guid(guid),
        },
    })?;
    let outcome = test_key(&a.pak, key);
    let label = match outcome {
        KeyTestOutcome::Verified => "verified",
        KeyTestOutcome::Decrypted => "decrypted (no index hash to verify)",
        KeyTestOutcome::WrongKey => "wrong key",
        KeyTestOutcome::Unsupported => "unsupported pak layout (key may be correct)",
    };
    println!("{}: {label}", a.id);
    // exit 1 if the key didn't work, 0 if it did
    Ok(u8::from(!matches!(
        outcome,
        KeyTestOutcome::Verified | KeyTestOutcome::Decrypted
    )))
}
