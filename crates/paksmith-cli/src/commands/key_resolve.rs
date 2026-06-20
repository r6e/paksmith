use std::path::Path;

use paksmith_core::container::pak::PakReader;
use paksmith_core::error::ProfileFault;
use paksmith_core::profile::resolve_key;
use paksmith_core::{AesKey, KeyGuid, PaksmithError, ProfileStore};

/// Resolve the AES key for a pak from `--aes-key` (wins) or `--game` (profile
/// lookup via the pak's footer GUID). Returns `None` when neither is set.
pub(crate) fn resolve_pak_key(
    path: &Path,
    aes_key: Option<&AesKey>,
    game: Option<&str>,
) -> paksmith_core::Result<Option<AesKey>> {
    if let Some(k) = aes_key {
        if game.is_some() {
            tracing::debug!("--aes-key overrides --game");
        }
        return Ok(Some(k.clone()));
    }
    let Some(id) = game else { return Ok(None) };
    let store = ProfileStore::load()?;
    let profile = store
        .profiles
        .get(id)
        .ok_or_else(|| PaksmithError::Profile {
            fault: ProfileFault::ProfileNotFound { id: id.to_string() },
        })?;
    let guid = PakReader::read_footer_guid(path)?;
    let key = resolve_key(profile, guid.as_ref()).ok_or_else(|| PaksmithError::Profile {
        fault: ProfileFault::NoKeyForGuid {
            id: id.to_string(),
            guid: guid.map_or_else(|| "default".into(), |g| KeyGuid::from_bytes(g).to_hex()),
        },
    })?;
    Ok(Some(key.clone()))
}
