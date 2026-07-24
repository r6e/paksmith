use std::path::Path;

use paksmith_core::AesKey;
use paksmith_core::profile::resolve::PakOpenContext;

/// CLI-side resolution: block_on the async core orchestration so the four
/// container commands keep a synchronous call site.
pub(crate) fn resolve_pak_key(
    path: &Path,
    aes_key: Option<&AesKey>,
    game: Option<&str>,
    detect: Option<&Path>,
) -> paksmith_core::Result<Option<AesKey>> {
    crate::block_on(paksmith_core::profile::resolve::resolve_pak_key(
        path, aes_key, game, detect,
    ))
}

/// Context-form resolution (#651): key + profile mappings source in one
/// call, for the commands that consume mappings (`inspect`, `extract`).
pub(crate) fn resolve_pak_context(
    path: &Path,
    aes_key: Option<&AesKey>,
    game: Option<&str>,
    detect: Option<&Path>,
) -> paksmith_core::Result<PakOpenContext> {
    crate::block_on(paksmith_core::profile::resolve::resolve_pak_context(
        path, aes_key, game, detect,
    ))
}
