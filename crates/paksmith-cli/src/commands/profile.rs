//! `paksmith profile` subcommand — add / list / show / remove profiles.
//!
//! Key verbs (`key add` / `key remove` / `test`) are Task 6 and are NOT
//! part of this module yet.

use std::collections::BTreeMap;

use clap::{Args, Subcommand};

use paksmith_core::error::ProfileFault;
use paksmith_core::profile::GameProfile;
use paksmith_core::{PaksmithError, ProfileStore};

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
pub(crate) fn run(cmd: &ProfileCmd, _format: OutputFormat) -> paksmith_core::Result<u8> {
    match cmd {
        ProfileCmd::Add(a) => add(a),
        ProfileCmd::List => list(),
        ProfileCmd::Show(a) => show(a),
        ProfileCmd::Remove(a) => remove(a),
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
        },
    );
    store.save()?;
    println!("added profile `{}`", a.id);
    Ok(0)
}

fn list() -> paksmith_core::Result<u8> {
    let store = ProfileStore::load()?;
    if store.profiles.is_empty() {
        println!("no profiles");
        return Ok(0);
    }
    for (id, p) in &store.profiles {
        let engine = p.engine_version.as_deref().unwrap_or("-");
        println!("{id}\t{}\t{engine}\t{} key(s)", p.name, p.keys.len());
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
    if !store.profiles.contains_key(&a.id) {
        return Err(PaksmithError::Profile {
            fault: ProfileFault::ProfileNotFound { id: a.id.clone() },
        });
    }
    let _ = store.profiles.remove(&a.id);
    store.save()?;
    println!("removed profile `{}`", a.id);
    Ok(0)
}
