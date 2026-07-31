//! `paksmith profile` subcommand — add / list / show / remove profiles,
//! plus key management (`key add` / `key remove`) and key testing (`test`).

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use clap::{Args, Subcommand};
use serde::Serialize;

use paksmith_core::error::ProfileFault;
use paksmith_core::{
    AesKey, GameProfile, KeyGuid, MappingsSource, PaksmithError, ProfileStore, ResolvedProfile,
    display_guid, resolve_profile_layered,
};

use crate::output::{OutputFormat, ResolvedFormat};

/// Profile management subcommands.
#[derive(Subcommand)]
pub(crate) enum ProfileCmd {
    /// Create a new profile
    Add(AddArgs),
    /// List local and cached registry profiles
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
    /// Engine version, e.g. `5.3` (`major.minor`, optional `.patch`,
    /// optional `UE` prefix). Consulted by inspect/extract for gates
    /// the package bytes leave ambiguous — notably UE 5.2 vs 5.3,
    /// which share one object version. Stored as given; an
    /// unparsable value warns and is ignored rather than failing.
    #[arg(long)]
    pub(crate) engine_version: Option<String>,
    /// `.usmap` mappings file this profile supplies when selected via
    /// `--game`/`--detect` (inspect/extract) for unversioned assets.
    /// Stored as-given; absolute paths recommended.
    #[arg(long, value_name = "PATH")]
    pub(crate) mappings: Option<std::path::PathBuf>,
    /// Glob pattern locating this game's archives (repeatable).
    /// Absolute patterns stand alone; relative patterns resolve against
    /// the `--detect` install dir at run time. Stored as-given.
    #[arg(long = "pak-path", value_name = "GLOB")]
    pub(crate) pak_paths: Vec<String>,
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

// ---------------------------------------------------------------------------
// `--format json` output shapes (#658)
// ---------------------------------------------------------------------------
//
// The repo's rule is SHARE a `schema_version` when the SHAPE is shared, keep
// it command-local when the shapes differ — `output.rs` versions `list` and
// `search` together *because* both emit the identical `EntryRow` through one
// writer, while `inspect` and `extract` version separately. No two of the
// READ documents below share a shape, so each carries its own. The four
// mutations DO share one (`MutationOutput`) and so share one constant — the
// `guid` two of them carry is an optional field on one shape, not a second
// shape, so a consumer that keys on `action` sees one document either way.
//
// `schema_version` is declared FIRST in every struct so serde emits it first;
// the raw-byte POSITION is what the tests pin, because asserting the key
// merely exists passes on any envelope.
//
// Key material: the guard is THIS MODULE, not the compiler. `AesKey` itself
// implements no `Serialize`, but that is not a barrier — `GameProfile` and
// `RegistryProfile` both derive `Serialize` and route `keys` through
// `keys_serde`, whose serializer calls `to_hex()`; that impl is what writes
// the on-disk store, so `serde_json::to_string(&profile)` compiles and emits
// every key. Never serialize a profile type directly here. Key material
// reaches JSON only through the hand-written `KeyRow` below, via one explicit
// `key_hex` call gated on `--show-keys`.

const PROFILE_LIST_SCHEMA_VERSION: u32 = 1;
const SHOW_SCHEMA_VERSION: u32 = 1;
const TEST_SCHEMA_VERSION: u32 = 1;
const FETCH_SCHEMA_VERSION: u32 = 1;
const MUTATION_SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
struct ListOutput {
    schema_version: u32,
    profiles: Vec<ProfileRow>,
}

#[derive(Serialize)]
struct ProfileRow {
    id: String,
    name: String,
    /// `null` rather than the table's `-`: JSON has a real absent value and a
    /// consumer should not need to know the sentinel.
    engine_version: Option<String>,
    key_count: usize,
    /// `"local"` or `"registry"` — the discriminant the table also renders.
    source: &'static str,
}

#[derive(Serialize)]
struct ShowOutput {
    schema_version: u32,
    id: String,
    source: &'static str,
    name: String,
    engine_version: Option<String>,
    /// `null` when absent — which covers BOTH a local profile with no
    /// mappings set and a registry profile, which cannot carry them at all.
    /// The document does not distinguish those; `source` does.
    mappings: Option<String>,
    pak_paths: Vec<String>,
    keys: Vec<KeyRow>,
}

#[derive(Serialize)]
struct KeyRow {
    guid: String,
    /// Present ONLY under `--show-keys`, mirroring the human path's deliberate
    /// reveal. OMITTED rather than `null` when redacted, unlike the absent
    /// fields elsewhere in this document: presence of the field IS the
    /// `--show-keys` signal, so a consumer tests `"key" in row` and needs no
    /// separate flag. (`null` would be indistinguishable from a future
    /// "profile has a key slot with no key".)
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,
}

#[derive(Serialize)]
struct TestOutput {
    schema_version: u32,
    id: String,
    /// A STABLE token, deliberately not the human label — the table renders
    /// prose ("decrypted (no index hash to verify)") that no script can match.
    outcome: &'static str,
    /// True iff the key opened the archive.
    ///
    /// NOT a mirror of the exit code, though it usually matches: a stdout that
    /// closes before this document is written masks the wrong-key 1 as 0
    /// (SPEC's BrokenPipe precedence), so `ok: false` can accompany exit 0.
    /// Branch on this field, not on the exit status.
    ok: bool,
}

#[derive(Serialize)]
struct FetchOutput {
    schema_version: u32,
    /// False when a fresh cache short-circuited the network call, so a script
    /// can tell "already current" from "downloaded".
    fetched: bool,
    /// How many profiles the fetched DOCUMENT carries.
    ///
    /// NOT `list.profiles`, which is an array of rows — and not even the same
    /// count: `list` renders the layered view. Named distinctly so one word
    /// cannot mean an array on one surface and an integer on another. The
    /// comparison that means something is this against the number of
    /// `source: "registry"` rows `list` returns (NOT `list`'s total, which
    /// counts local rows too); any gap is entries collapsed by shadowing or
    /// repetition, and the counts alone cannot say which.
    profile_count: usize,
}

/// The receipt every store-mutating subcommand returns under `--format json`.
///
/// One shape for all four (`add`, `remove`, `key add`, `key remove`) because
/// they answer the same question — what happened, to which profile — so they
/// share one `schema_version` under the rule stated above.
///
/// These commands emitting a document at all is deliberate. The alternative
/// (a confirmation line rerouted to stderr, leaving stdout empty) meant
/// `--format json` produced ZERO bytes on stdout, which is not parseable
/// JSON: `serde_json::from_reader` errors on empty input. It also forced the
/// stream a message lands on to depend on a formatting flag, and made the
/// "emitting JSON" advisory note say something untrue.
#[derive(Serialize)]
struct MutationOutput {
    schema_version: u32,
    /// A STABLE token, not the human sentence: `added`, `removed`,
    /// `key_added`, `key_removed`.
    action: &'static str,
    id: String,
    /// The key slot the two `key` subcommands acted on; omitted for `add` and
    /// `remove`, which have none.
    ///
    /// Carried because without it the receipt is the ONE place in this family
    /// where the machine output says less than the human line it replaces:
    /// the table names the GUID, and `key add --guid` is optional, so an
    /// omitted flag means the slot is computed in-handler (the all-zero
    /// default) and would never reach the caller at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    guid: Option<String>,
}

/// `ProfileNotFound` for `id`. Both wrappers below build it identically.
fn profile_not_found(id: &str) -> PaksmithError {
    PaksmithError::Profile {
        fault: ProfileFault::ProfileNotFound { id: id.to_string() },
    }
}

/// Resolve `id` across the local store and the registry cache (local wins), or
/// fail with `ProfileNotFound` (#658).
///
/// OFFLINE ONLY, and deliberately unlike `--game`/`--detect`: those auto-fetch
/// when the cache is stale or lacks the id (`resolve_pak_context`), because
/// they are on their way to opening an archive. These are read/diagnostic
/// commands, and a `show` that silently hits the network is surprising — so an
/// id that exists only in a never-fetched registry document does NOT resolve
/// here. The hint on the failure path says so rather than leaving the user to
/// infer it from a command that works with `--game` and not with `show`.
///
/// The same asymmetry means a STALE cache is reported as-is: `test` can call a
/// key wrong that `--game` would refresh and accept. `test` says so at the
/// moment it happens (see `test`); the contract is also recorded in ROADMAP
/// §Phase 5.
fn resolve_layered_or_not_found<'a>(
    store: &'a ProfileStore,
    cache: Option<&'a paksmith_core::profile::cache::RegistryCache>,
    id: &str,
    quiet: bool,
) -> paksmith_core::Result<ResolvedProfile<'a>> {
    resolve_profile_layered(store, cache, id).ok_or_else(|| {
        crate::output::note(
            quiet,
            &format!(
                "`{id}` is in neither the local store nor the cached registry; \
                 if it is a registry profile, run `paksmith profile fetch` first"
            ),
        );
        profile_not_found(id)
    })
}

/// PRINTS a remediation hint to stderr, then returns `ProfileNotFound`, for a
/// command that MUTATES the local store (#658).
///
/// Side-effecting by design — it reads the registry cache and may write a
/// `note:` line — so the name says so rather than reading as pure
/// construction.
///
/// `show`/`test` resolve registry profiles, so a bare "no profile named `x`"
/// from `remove`/`key add`/`key remove` is factually false one command later.
/// Registry profiles are genuinely read-only — the cached document is
/// ed25519-signed and re-fetched wholesale — so the exit code stands; only the
/// wording needed to stop lying. Follows the remediation-hint precedent
/// `ProfileFault::NoPakPaths` already sets for the same local/registry split,
/// CLI-side so core's wire-stable `Display` set is untouched.
fn hint_read_only_then_not_found(id: &str, quiet: bool) -> PaksmithError {
    let cache = paksmith_core::profile::resolve::load_cache_lenient();
    if cache.as_ref().and_then(|c| c.get(id)).is_some() {
        // Command-NEUTRAL: `remove` asks to delete, so telling it to `add`
        // points the wrong way (and the shadow would not even achieve what it
        // wanted — the id reappears, tagged `[local]`).
        crate::output::note(
            quiet,
            &format!(
                "`{id}` comes from the signed registry document and cannot be \
                 edited or deleted locally; `paksmith profile fetch` refreshes \
                 it, and `paksmith profile add {id} --name <name>` creates a \
                 local profile that shadows it"
            ),
        );
    }
    profile_not_found(id)
}

/// Current Unix time in seconds (CLI-local; core's `now_unix` is `pub(crate)`).
fn now_unix() -> paksmith_core::Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| paksmith_core::PaksmithError::InvalidArgument {
            arg: "clock",
            reason: e.to_string(),
        })
}

/// Dispatch a [`ProfileCmd`] and return a process exit code byte.
///
/// `--format json` (#658) covers EVERY subcommand: the ones returning data
/// (`list`, `show`, `detect`), the ones returning a result a script branches
/// on (`test`, `fetch`), and the four store mutations, which emit a
/// [`MutationOutput`] receipt. Uniform coverage is what lets the advisory
/// note below fire unconditionally and be true — a partially-JSON family
/// would need the note gated per subcommand, and would leave `profile add
/// --format json` writing zero unparsable bytes to stdout.
pub(crate) fn run(
    cmd: &ProfileCmd,
    format: OutputFormat,
    quiet: bool,
) -> paksmith_core::Result<u8> {
    let fmt = format.resolve();
    // `profile` resolves `--format auto` exactly as `list`/`search`/`inspect`
    // do — JSON when stdout is not a TTY — so the advisory warning about that
    // surprise must fire here too, or piping `profile list` silently changes
    // shape.
    crate::output::note_auto_resolved_to_json(format, fmt, quiet);
    match cmd {
        ProfileCmd::Add(a) => add(a, fmt),
        ProfileCmd::List => list(fmt),
        ProfileCmd::Show(a) => show(a, fmt, quiet),
        ProfileCmd::Remove(a) => remove(a, fmt, quiet),
        ProfileCmd::Key { cmd } => match cmd {
            KeyCmd::Add(a) => key_add(a, fmt, quiet),
            KeyCmd::Remove(a) => key_remove(a, fmt, quiet),
        },
        ProfileCmd::Test(a) => test(a, fmt, quiet),
        ProfileCmd::Fetch(a) => fetch(a, fmt),
        ProfileCmd::Detect(a) => crate::commands::detect::run(&a.dir, fmt),
    }
}

/// A completed store mutation.
///
/// An enum rather than parallel `msg` / `action` / `id` / `guid` arguments:
/// those were four positional values, two of them `&str` and therefore
/// swappable with no compile error, and nothing tied the prose to the wire
/// token — `confirm(fmt, "removed profile `x`", "added", …)` was expressible.
enum Mutation<'a> {
    Added { id: &'a str },
    Removed { id: &'a str },
    KeyAdded { id: &'a str, guid: KeyGuid },
    KeyRemoved { id: &'a str, guid: KeyGuid },
}

/// Report a completed store mutation: the human sentence under `--format
/// table`, a [`MutationOutput`] receipt under `--format json`.
///
/// ONE exhaustive match yields the wire token, the id, the key slot and the
/// prose together, so each token sits beside the sentence it corresponds to
/// and a fifth mutation cannot ship without choosing all four. Four separate
/// accessor matches would put the pairing back on convention — nothing would
/// stop `Added => "removed"` in one of them — which is the same reason
/// `test` derives `(token, ok, label)` from a single match rather than
/// pairing an exhaustive match with a `matches!`.
fn confirm(fmt: ResolvedFormat, m: &Mutation<'_>) -> io::Result<()> {
    let (action, id, guid, sentence) = match *m {
        Mutation::Added { id } => ("added", id, None, format!("added profile `{id}`")),
        Mutation::Removed { id } => ("removed", id, None, format!("removed profile `{id}`")),
        Mutation::KeyAdded { id, guid } => (
            "key_added",
            id,
            Some(guid),
            format!("added key for GUID {} to `{id}`", guid.to_hex()),
        ),
        Mutation::KeyRemoved { id, guid } => (
            "key_removed",
            id,
            Some(guid),
            format!("removed key for GUID {} from `{id}`", guid.to_hex()),
        ),
    };
    match fmt {
        ResolvedFormat::Table => crate::output::print_line(&sentence),
        ResolvedFormat::Json => crate::output::print_json(&MutationOutput {
            schema_version: MUTATION_SCHEMA_VERSION,
            action,
            id: id.to_string(),
            guid: guid.map(|g| g.to_hex()),
        }),
    }
}

fn add(a: &AddArgs, fmt: ResolvedFormat) -> paksmith_core::Result<u8> {
    // Validate every layer (CLAUDE.md): a syntactically invalid glob is
    // rejected HERE, not stored to fail at first expansion. Empty is
    // checked explicitly — `glob` compiles "" without complaint.
    for pattern in &a.pak_paths {
        if pattern.is_empty() {
            return Err(PaksmithError::InvalidArgument {
                arg: "--pak-path",
                reason: "empty pattern".to_string(),
            });
        }
        if let Err(e) = glob::Pattern::new(pattern) {
            return Err(PaksmithError::InvalidArgument {
                arg: "--pak-path",
                reason: format!("`{pattern}` is not a valid glob: {e}"),
            });
        }
    }
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
            mappings: a.mappings.clone().map(MappingsSource::Path),
            pak_paths: a.pak_paths.clone(),
        },
    );
    store.save()?;
    confirm(fmt, &Mutation::Added { id: &a.id })?;
    Ok(0)
}

/// Every profile the layered view exposes, in the order both arms render:
/// local ids first (`BTreeMap`-sorted), then registry-only ids in
/// registry-document order.
///
/// THE local-wins precedence rule, in one place, feeding both arms — so the
/// human and machine views of one store cannot drift. In JSON a drifted copy
/// is worse than cosmetic: a shadowed id would appear TWICE in an array
/// consumers key by id.
///
/// `source` is likewise derived once. The table renders it as `[local]` /
/// `[registry]` and the JSON row emits it verbatim, so the human label and
/// the wire token cannot disagree.
///
/// Ids are unique in the result, and that takes TWO rules, not one. A local id
/// shadows a registry one; and a registry document may itself repeat an id,
/// because `validate_caps` bounds the profile count and string lengths but
/// never checks uniqueness. First occurrence wins, which is what
/// `RegistryCache::get` already does (`.find()`) — so `list` and `show` answer
/// with the same profile rather than disagreeing about the same store.
///
/// Core implements the same two rules in
/// `profile::resolve::unshadowed_registry`, for `detect` and the GUI's profile
/// list. They are separate because that helper is private to its module and
/// unreachable across the crate boundary — not because of its item type, which
/// is `&RegistryProfile` and carries everything this needs. If either side
/// changes precedence, `list` and `detect` start naming different profiles for
/// one id — change them together.
fn profile_rows(
    store: &ProfileStore,
    cache: Option<&paksmith_core::RegistryCache>,
) -> Vec<ProfileRow> {
    let mut rows: Vec<ProfileRow> = store
        .profiles
        .iter()
        .map(|(id, p)| ProfileRow {
            id: id.clone(),
            name: p.name.clone(),
            engine_version: p.engine_version.clone(),
            key_count: p.keys.len(),
            source: "local",
        })
        .collect();
    if let Some(c) = cache {
        // Seeded with the local ids so one pass enforces both rules.
        let mut seen: BTreeSet<&str> = store.profiles.keys().map(String::as_str).collect();
        for p in &c.doc.profiles {
            if !seen.insert(p.id.as_str()) {
                continue;
            }
            rows.push(ProfileRow {
                id: p.id.clone(),
                name: p.name.clone(),
                engine_version: p.engine_version.clone(),
                key_count: p.keys.len(),
                source: "registry",
            });
        }
    }
    rows
}

fn list(fmt: ResolvedFormat) -> paksmith_core::Result<u8> {
    let store = ProfileStore::load()?;
    let cache = paksmith_core::profile::resolve::load_cache_lenient();
    let profiles = profile_rows(&store, cache.as_ref());

    if matches!(fmt, ResolvedFormat::Json) {
        let out = ListOutput {
            schema_version: PROFILE_LIST_SCHEMA_VERSION,
            profiles,
        };
        crate::output::print_json(&out)?;
        return Ok(0);
    }

    if profiles.is_empty() {
        crate::output::print_line("no profiles")?;
        return Ok(0);
    }

    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    for r in &profiles {
        let engine = r.engine_version.as_deref().unwrap_or("-");
        writeln!(
            out,
            "{}\t{}\t{engine}\t{} key(s)\t[{}]",
            r.id, r.name, r.key_count, r.source
        )?;
    }
    out.flush()?;
    Ok(0)
}

fn show(a: &ShowArgs, fmt: ResolvedFormat, quiet: bool) -> paksmith_core::Result<u8> {
    let store = ProfileStore::load()?;
    let cache = paksmith_core::profile::resolve::load_cache_lenient();
    let resolved = resolve_layered_or_not_found(&store, cache.as_ref(), &a.id, quiet)?;

    // Only the ASYMMETRIC fields are matched: a registry profile structurally
    // carries no `mappings` and no `pak_paths` (see `MappingsSource`'s registry
    // note), and an explicit match is what keeps that visible. Everything both
    // arms agree on goes through the accessors.
    let (mappings, pak_paths) = match resolved {
        ResolvedProfile::Local(p) => (p.mappings.as_ref(), p.pak_paths.as_slice()),
        ResolvedProfile::Registry(_) => (None, [].as_slice()),
    };

    // The `--show-keys` reveal gate, expressed ONCE and consumed by both
    // arms. Two independent gates (one per arm) meant two `key_hex` call
    // sites whose agreement was a convention; this is now the crate's only
    // `key_hex` call, so the redaction story has a single place to audit.
    let keys: Vec<KeyRow> = resolved
        .keys()
        .iter()
        .map(|(guid, key)| KeyRow {
            guid: guid.to_hex(),
            // Deliberate reveal: only `--show-keys` renders key material.
            key: a.show_keys.then(|| paksmith_core::profile::key_hex(key)),
        })
        .collect();

    if matches!(fmt, ResolvedFormat::Json) {
        let out = ShowOutput {
            schema_version: SHOW_SCHEMA_VERSION,
            id: a.id.clone(),
            source: resolved.source(),
            name: resolved.name().to_string(),
            engine_version: resolved.engine_version().map(str::to_string),
            mappings: mappings.map(|MappingsSource::Path(path)| path.display().to_string()),
            pak_paths: pak_paths.iter().map(ToString::to_string).collect(),
            keys,
        };
        crate::output::print_json(&out)?;
        return Ok(0);
    }

    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    writeln!(out, "id: {}", a.id)?;
    writeln!(out, "source: {}", resolved.source())?;
    writeln!(out, "name: {}", resolved.name())?;
    writeln!(
        out,
        "engine_version: {}",
        resolved.engine_version().unwrap_or("-")
    )?;
    match mappings {
        // Not key material — safe to show unredacted.
        Some(MappingsSource::Path(path)) => {
            writeln!(out, "mappings: {}", path.display())?;
        }
        None => writeln!(out, "mappings: -")?,
    }
    // Not key material — safe to show unredacted (mappings precedent).
    if pak_paths.is_empty() {
        writeln!(out, "pak_paths: -")?;
    } else {
        writeln!(out, "pak_paths:")?;
        for pattern in pak_paths {
            writeln!(out, "  {pattern}")?;
        }
    }
    writeln!(out, "keys:")?;
    for row in &keys {
        match &row.key {
            Some(k) => writeln!(out, "  {} = {k}", row.guid)?,
            None => writeln!(out, "  {} = <redacted>", row.guid)?,
        }
    }
    out.flush()?;
    Ok(0)
}

fn remove(a: &RemoveArgs, fmt: ResolvedFormat, quiet: bool) -> paksmith_core::Result<u8> {
    let mut store = ProfileStore::load()?;
    if store.profiles.remove(&a.id).is_none() {
        return Err(hint_read_only_then_not_found(&a.id, quiet));
    }
    store.save()?;
    confirm(fmt, &Mutation::Removed { id: &a.id })?;
    Ok(0)
}

fn key_add(a: &KeyAddArgs, fmt: ResolvedFormat, quiet: bool) -> paksmith_core::Result<u8> {
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
        .ok_or_else(|| hint_read_only_then_not_found(&a.id, quiet))?;
    let _ = p.keys.insert(guid, key);
    store.save()?;
    confirm(fmt, &Mutation::KeyAdded { id: &a.id, guid })?;
    Ok(0)
}

fn key_remove(a: &KeyRemoveArgs, fmt: ResolvedFormat, quiet: bool) -> paksmith_core::Result<u8> {
    let guid = KeyGuid::from_hex(&a.guid).map_err(|e| PaksmithError::InvalidArgument {
        arg: "--guid",
        reason: e.to_string(),
    })?;
    let mut store = ProfileStore::load()?;
    let p = store
        .profiles
        .get_mut(&a.id)
        .ok_or_else(|| hint_read_only_then_not_found(&a.id, quiet))?;
    if p.keys.remove(&guid).is_none() {
        return Err(PaksmithError::Profile {
            fault: ProfileFault::NoKeyForGuid {
                id: a.id.clone(),
                guid: guid.to_hex(),
            },
        });
    }
    store.save()?;
    confirm(fmt, &Mutation::KeyRemoved { id: &a.id, guid })?;
    Ok(0)
}

/// Report `fetch`'s outcome: the wire flag and its prose paired in ONE match,
/// in the [`confirm`]/[`outcome_report`] style — the two emit paths repeated
/// the `FetchOutput` construction and the format branch verbatim, differing
/// only in the flag, the count and the sentence.
fn report_fetch(fmt: ResolvedFormat, fetched: bool, profile_count: usize) -> io::Result<()> {
    match fmt {
        ResolvedFormat::Json => crate::output::print_json(&FetchOutput {
            schema_version: FETCH_SCHEMA_VERSION,
            fetched,
            profile_count,
        }),
        ResolvedFormat::Table => {
            let sentence = if fetched {
                format!("fetched {profile_count} profiles")
            } else {
                format!(
                    "registry cache is fresh ({profile_count} profiles); use --force to re-fetch"
                )
            };
            crate::output::print_line(&sentence)
        }
    }
}

fn fetch(a: &FetchArgs, fmt: ResolvedFormat) -> paksmith_core::Result<u8> {
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

    let now = now_unix()?;

    // A corrupt/unreadable cache degrades to `None` (warn) so `profile fetch`
    // proceeds to fetch a fresh copy — it overwrites the cache anyway, so a
    // bad existing file must never block the recovery path.
    if !a.force
        && let Some(existing) = paksmith_core::profile::resolve::load_cache_lenient()
        && !existing.is_stale(now, staleness_hours)
    {
        report_fetch(fmt, false, existing.doc.profiles.len())?;
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
    report_fetch(fmt, true, cache.doc.profiles.len())?;
    Ok(0)
}

/// The wire token, the `ok` flag and the human label for one key-test outcome.
///
/// A PURE function over the enum, in the seam style of
/// [`crate::output::OutputFormat::resolve_with_tty`], because `test()` cannot
/// reach every arm from a fixture. `Unsupported` comes from `test_key`'s
/// catch-all `Err(_)` on a non-`Decryption` open failure, and the corpus has
/// no pak that parses a footer and then fails that way — so routing every arm
/// through the command left `Unsupported`'s token, its label AND its exit-1
/// contract unpinned. A mutant returning `("verified", true, …)` for it
/// survived the entire workspace suite.
///
/// Returns a NAMED struct rather than a `(token, ok, label)` triple: two of
/// the three are `&'static str` and a positional pair is exactly the
/// swappable-with-no-compile-error shape `Mutation` exists to avoid.
///
/// All three values come from ONE match so they cannot drift apart: a
/// `matches!(outcome, Verified | Decrypted)` for `ok` is not
/// exhaustiveness-checked, so a fifth variant would flag the token arm at
/// compile time while silently becoming `ok: false` and exit 1.
#[derive(Debug, PartialEq, Eq)]
struct OutcomeReport {
    /// The STABLE wire token.
    token: &'static str,
    /// Drives the exit code via `u8::from(!ok)`.
    ok: bool,
    /// The human sentence, deliberately prose the token is not.
    label: &'static str,
}

fn outcome_report(outcome: &paksmith_core::profile::key_test::KeyTestOutcome) -> OutcomeReport {
    use paksmith_core::profile::key_test::KeyTestOutcome;
    let (token, ok, label) = match outcome {
        KeyTestOutcome::Verified => ("verified", true, "verified"),
        KeyTestOutcome::Decrypted => ("decrypted", true, "decrypted (no index hash to verify)"),
        KeyTestOutcome::WrongKey => ("wrong_key", false, "wrong key"),
        KeyTestOutcome::Unsupported => (
            "unsupported",
            false,
            "unsupported pak layout (key may be correct)",
        ),
    };
    OutcomeReport { token, ok, label }
}

fn test(a: &TestArgs, fmt: ResolvedFormat, quiet: bool) -> paksmith_core::Result<u8> {
    use paksmith_core::container::pak::PakReader;
    use paksmith_core::profile::key_test::{KeyTestOutcome, test_key};

    let store = ProfileStore::load()?;
    let cache = paksmith_core::profile::resolve::load_cache_lenient();
    let resolved = resolve_layered_or_not_found(&store, cache.as_ref(), &a.id, quiet)?;
    let guid = PakReader::read_footer_guid(&a.pak)?;
    let key = resolved
        .resolve_key(guid.as_ref())
        .ok_or_else(|| PaksmithError::Profile {
            fault: ProfileFault::NoKeyForGuid {
                id: a.id.clone(),
                guid: display_guid(guid),
            },
        })?;
    let outcome = test_key(&a.pak, key);
    // C2: `--game`/`--detect` auto-refresh a stale registry document; these
    // read commands do not (see `resolve_layered_or_not_found`). So a
    // registry-sourced key can test WRONG here while `extract --game` refreshes
    // and succeeds — and this is the command a user reaches for to explain
    // that very failure.
    //
    // Discriminant, NOT `source() == "registry"`: that method's job is
    // rendering, so branching on it would let a label rename silently disable
    // the note across a crate boundary.
    if matches!(outcome, KeyTestOutcome::WrongKey)
        && matches!(resolved, ResolvedProfile::Registry(_))
    {
        crate::output::note(
            quiet,
            &format!(
                "`{}` came from the cached registry document, which these \
                 commands never refresh; if `--game` works where this does \
                 not, the cache is stale — run `paksmith profile fetch`",
                a.id
            ),
        );
    }
    let OutcomeReport { token, ok, label } = outcome_report(&outcome);
    if matches!(fmt, ResolvedFormat::Json) {
        let out = TestOutput {
            schema_version: TEST_SCHEMA_VERSION,
            id: a.id.clone(),
            outcome: token,
            ok,
        };
        crate::output::print_json(&out)?;
        return Ok(u8::from(!ok));
    }
    crate::output::print_line(&format!("{}: {label}", a.id))?;
    // exit 1 if the key didn't work, 0 if it did
    Ok(u8::from(!ok))
}

#[cfg(test)]
mod tests {
    use super::{OutcomeReport, outcome_report};
    use paksmith_core::profile::key_test::KeyTestOutcome;

    /// Every arm of the key-test report, including the one no fixture reaches.
    ///
    /// `Unsupported` is the point: through the command it is unreachable, so
    /// its token, label and `ok` were all unpinned and a mutant claiming
    /// `("verified", true, …)` for it passed the whole suite. `ok` is the
    /// part that matters — it drives `Ok(u8::from(!ok))`, so flipping it turns
    /// SPEC's exit 1 for an untestable layout into a silent success.
    #[test]
    fn outcome_report_pins_every_arm() {
        let expect = |outcome, token, ok, label| {
            assert_eq!(
                outcome_report(&outcome),
                OutcomeReport { token, ok, label },
                "report for {outcome:?}"
            );
        };
        expect(KeyTestOutcome::Verified, "verified", true, "verified");
        expect(
            KeyTestOutcome::Decrypted,
            "decrypted",
            true,
            "decrypted (no index hash to verify)",
        );
        expect(KeyTestOutcome::WrongKey, "wrong_key", false, "wrong key");
        expect(
            KeyTestOutcome::Unsupported,
            "unsupported",
            false,
            "unsupported pak layout (key may be correct)",
        );
    }

    /// The wire tokens and the human labels must stay distinct vocabularies:
    /// the JSON token exists BECAUSE the table renders prose no script can
    /// match on. A label edit that copied another outcome's text, or a token
    /// that drifted into prose, would defeat that.
    #[test]
    fn outcome_tokens_are_machine_values_and_labels_are_not() {
        // `Verified` is the one arm where token and label legitimately agree.
        let cases = [
            (KeyTestOutcome::Verified, true),
            (KeyTestOutcome::Decrypted, false),
            (KeyTestOutcome::WrongKey, false),
            (KeyTestOutcome::Unsupported, false),
        ];
        let mut tokens = Vec::new();
        for (outcome, token_equals_label) in cases {
            let OutcomeReport { token, label, .. } = outcome_report(&outcome);
            assert!(
                !token.contains(' '),
                "a wire token must not be prose, got {token:?}"
            );
            if token_equals_label {
                assert_eq!(token, label);
            } else {
                assert_ne!(token, label, "token and label must differ: {token:?}");
            }
            tokens.push(token);
        }
        tokens.sort_unstable();
        tokens.dedup();
        assert_eq!(tokens.len(), 4, "all four tokens must be distinct");
    }
}
