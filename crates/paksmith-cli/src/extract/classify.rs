//! Classify a pak entry by extension to choose its extract path.

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum EntryClass {
    /// `.uasset` / `.umap` — parse + convert via the handler registry.
    Asset,
    /// `.uexp` / `.ubulk` / `.uptnl` — consumed by the asset parse; never emitted.
    Companion,
    /// Anything else — copy raw.
    Raw,
}

pub(crate) fn classify(entry_path: &str) -> EntryClass {
    // Extension is taken from the final path component only, and a leading
    // dot does NOT start an extension (".uasset" / "Game/.uasset" are
    // hidden files with no extension → Raw).
    let file_name = crate::path_util::basename(entry_path);
    let ext = crate::path_util::extension_of(file_name);

    match ext.as_deref() {
        Some("uasset" | "umap") => EntryClass::Asset,
        Some("uexp" | "ubulk" | "uptnl") => EntryClass::Companion,
        _ => EntryClass::Raw,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_assets() {
        assert_eq!(classify("Game/Hero.uasset"), EntryClass::Asset);
        assert_eq!(classify("Game/Level.umap"), EntryClass::Asset);
        assert_eq!(classify("HERO.UASSET"), EntryClass::Asset); // case-insensitive
    }

    #[test]
    fn classifies_companions() {
        for p in ["Hero.uexp", "Hero.ubulk", "Hero.uptnl"] {
            assert_eq!(classify(p), EntryClass::Companion, "{p}");
        }
    }

    #[test]
    fn classifies_raw() {
        for p in ["Config.ini", "Strings.locres", "noext", "data.bin"] {
            assert_eq!(classify(p), EntryClass::Raw, "{p}");
        }
    }

    #[test]
    fn dotfiles_have_no_extension() {
        // Leading-dot files are hidden files, not assets.
        assert_eq!(classify(".uasset"), EntryClass::Raw);
        assert_eq!(classify("Game/.uexp"), EntryClass::Raw);
    }

    #[test]
    fn directory_dot_does_not_count_as_extension() {
        // A dot in a directory name, with no extension on the file → Raw.
        assert_eq!(classify("dir.uasset/file"), EntryClass::Raw);
    }

    #[test]
    fn rightmost_extension_wins() {
        assert_eq!(classify("a.tar.uasset"), EntryClass::Asset);
    }
}
