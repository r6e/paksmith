//! Classify a pak entry by extension to choose its extract path.

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum EntryClass {
    /// `.uasset` / `.umap` — parse + convert via the handler registry.
    Asset,
    /// `.uexp` / `.ubulk` / `.uptnl` — consumed by the asset parse; never emitted.
    Companion,
    /// Anything else — copy raw.
    Raw,
}

#[allow(dead_code)]
pub(crate) fn classify(entry_path: &str) -> EntryClass {
    let ext = entry_path
        .rsplit('.')
        .next()
        .filter(|e| !e.contains('/') && *e != entry_path)
        .map(str::to_ascii_lowercase);

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
}
