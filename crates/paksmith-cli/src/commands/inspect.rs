//! `paksmith inspect [pak] <asset>` — or `inspect <asset>` with a
//! `--game`/`--detect` profile supplying the archives — dump a uasset's parsed
//! shape as JSON.
//!
//! The output covers the structural header (summary, name table,
//! imports, exports, custom versions, engine version) PLUS each
//! export's typed [`paksmith_core::Asset`] payload under an
//! `"asset"` field. Phase 3 ships only the `Generic` variant, so
//! the per-export shape is
//! `"asset": {"Generic": {"kind": "tree", "properties": [...]}}`
//! for decoded property streams and
//! `"asset": {"Generic": {"kind": "opaque", "bytes": N}}` for
//! iterator-failure fallbacks (byte count only — raw bytes are
//! omitted to keep CLI output bounded). Phase 3 sub-phases (3d-3h)
//! add typed variants — `"asset": {"DataTable": {...}}`,
//! `"asset": {"Texture2D": {...}}`, etc. — under the same
//! externally-tagged shape.
//!
//! Pass `--mappings <file.usmap>` to decode `.usmap`-driven
//! unversioned assets that would otherwise reject with
//! `UnversionedWithoutMappings` — or select a mappings-bearing profile
//! with `--game`/`--detect` (an explicit `--mappings` wins; see
//! `commands::mappings_resolve`).

use std::path::PathBuf;

use clap::Args;

use paksmith_core::AesKey;
use paksmith_core::asset::Package;

use crate::output::OutputFormat;

#[derive(Args)]
pub(crate) struct InspectArgs {
    // Clap cannot put an optional positional before a required one, so
    // the single positional does double duty (the `git diff
    // [commit] [path]` pattern) — arity picks the reading.
    /// Path to the .pak file — or, when this is the only positional and
    /// `--game`/`--detect` selects a profile with `pak_paths`, the
    /// asset virtual path itself: the asset is then located across the
    /// profile's archives (ambiguity is an error).
    #[arg(value_name = "PAK|ASSET")]
    pub(crate) pak_or_asset: String,
    /// Virtual path of the asset within the archive. Omit it to use the
    /// profile-paks form (single positional = the asset).
    #[arg(value_name = "ASSET")]
    pub(crate) asset: Option<String>,
    /// Optional `.usmap` mappings file. Required for assets whose
    /// `PKG_UnversionedProperties` flag is set (UE 4.25+ cooked
    /// content; common in both UE4 and UE5 shipping games).
    /// Versioned (tagged-property) assets parse without it. Wins over
    /// the mappings source of a `--game`/`--detect`-selected profile.
    #[arg(long, value_name = "PATH")]
    pub(crate) mappings: Option<PathBuf>,
    /// Emit only the value at this dotted path (e.g. `summary.guid`,
    /// `exports.0.asset`). Implies structured output; cannot combine with
    /// `--format table`.
    #[arg(long, value_name = "DOTTED")]
    pub(crate) path: Option<String>,
    /// Emit only a single export: a numeric export-table index, or an export
    /// object name. Errors on an unknown/ambiguous name or out-of-range index.
    #[arg(long, value_name = "IDX|NAME")]
    pub(crate) export: Option<String>,
}

/// Run the `inspect` subcommand.
///
/// Resolves the pak-open context (key + any profile mappings source),
/// loads the effective usmap (explicit `--mappings` wins — see
/// [`crate::commands::mappings_resolve`]), parses the package, then
/// delegates all output assembly — format resolution, `--export`
/// selection, `--path` drilling, and the `--format table` human tree
/// view — to [`crate::inspect::emit`].
pub(crate) fn run(
    args: &InspectArgs,
    format: OutputFormat,
    aes_key: Option<&AesKey>,
    game: Option<&str>,
    detect: Option<&std::path::Path>,
    quiet: bool,
) -> paksmith_core::Result<()> {
    // Two positionals = pak + asset (pre-#655 shape, byte-identical
    // behavior); one positional = the asset, sourced via profile paks.
    let (explicit_pak, asset): (Option<PathBuf>, &str) = match args.asset.as_deref() {
        Some(a) => (Some(PathBuf::from(&args.pak_or_asset)), a),
        None => (None, args.pak_or_asset.as_str()),
    };
    // The classic forgot-the-asset slip (`paksmith inspect Foo.pak`)
    // would otherwise surface core's "no pak path given" message —
    // confusing, since the user DID type a path (it was read as the
    // asset). Name both forms instead.
    if explicit_pak.is_none() && game.is_none() && detect.is_none() {
        return Err(paksmith_core::PaksmithError::InvalidArgument {
            arg: "PAK|ASSET",
            reason: "expected `inspect <PAK> <ASSET>`, or `--game <ID>`/`--detect <DIR>` \
                     with `inspect <ASSET>` to search a profile's archives"
                .to_string(),
        });
    }
    let sources = crate::profile_paks::resolve_pak_sources(explicit_pak.as_deref(), game, detect)?;
    let pak = select_containing_pak(sources, asset, aes_key, game, detect)?;
    let ctx = crate::commands::key_resolve::resolve_pak_context(&pak, aes_key, game, detect)?;
    let usmap = crate::commands::mappings_resolve::resolve_usmap(
        args.mappings.as_deref(),
        ctx.mappings.as_ref(),
        crate::commands::mappings_resolve::mappings_selector(game),
    )?;
    let reader = paksmith_core::container::open(&pak, ctx.key.as_ref())?;
    let pkg = Package::read_from_reader(&reader, asset, usmap.as_ref())?;
    crate::inspect::emit(&pkg, args, format, quiet)
}

/// The single archive containing `asset`. One source (an explicit pak
/// path) passes through untouched — the subsequent read reports a
/// missing asset exactly as pre-#655. Across a profile's archives the
/// policy is fail-closed: found in none is `EntryNotFound`, found in
/// several is an error naming them (pass an explicit path to pick one).
fn select_containing_pak(
    mut sources: Vec<PathBuf>,
    asset: &str,
    aes_key: Option<&AesKey>,
    game: Option<&str>,
    detect: Option<&std::path::Path>,
) -> paksmith_core::Result<PathBuf> {
    if sources.len() == 1 {
        return Ok(sources.remove(0));
    }
    let mut containing = Vec::new();
    for pak in sources {
        let key = crate::commands::key_resolve::resolve_pak_key(&pak, aes_key, game, detect)?;
        let reader = paksmith_core::container::open(&pak, key.as_ref())?;
        if reader.entries().any(|e| e.path() == asset) {
            containing.push(pak);
        }
    }
    match containing.len() {
        1 => Ok(containing.remove(0)),
        0 => Err(paksmith_core::PaksmithError::EntryNotFound {
            path: asset.to_string(),
        }),
        _ => Err(paksmith_core::PaksmithError::InvalidArgument {
            arg: "asset",
            reason: format!(
                "`{asset}` exists in multiple archives ({}); pass an explicit pak path",
                crate::profile_paks::join_display(&containing)
            ),
        }),
    }
}
