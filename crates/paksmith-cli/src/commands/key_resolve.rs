use std::path::Path;

use paksmith_core::AesKey;
use paksmith_core::profile::resolve::PakOpenContext;

/// CLI-side key-only resolution: block_on the async core orchestration
/// so `list`/`search` (which never consume mappings) keep a synchronous
/// call site; `inspect`/`extract` use [`resolve_pak_context`] below.
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

/// Context-form resolution: the key plus the profile's parse inputs —
/// mappings source (#651) and engine version (#656) — in one call, for
/// the commands that parse assets (`inspect`, `extract`).
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
