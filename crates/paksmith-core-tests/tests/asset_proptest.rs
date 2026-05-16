//! Property-based tests for uasset header components (Phase 2a).
//!
//! Seven properties spanning the wire-format round-trip identity and
//! the structural-cap rejection arms:
//!
//! 1. **`engine_version_round_trip`** — `EngineVersion::write_to` →
//!    `EngineVersion::read_from` is the identity over strategy-
//!    generated (u16, u16, u16, u32, ASCII-ish branch) tuples.
//! 2. **`custom_version_container_round_trip`** — same identity for
//!    `CustomVersionContainer` over 0..16 random `(FGuid, i32)` rows.
//! 3. **`name_table_round_trip`** — same identity for `NameTable`
//!    over 0..32 ASCII-identifier-shaped names.
//! 4. **`name_table_rejects_count_over_cap`** — `count >
//!    MAX_NAME_TABLE_ENTRIES` produces `BoundsExceeded { field:
//!    NameCount, .. }`.
//! 5. **`import_table_round_trip`** — same identity for `ImportTable`
//!    over 0..8 imports (UE4.27 version → no `import_optional` tail).
//! 6. **`import_count_cap_rejection`** — `count >
//!    MAX_IMPORT_TABLE_ENTRIES` produces `BoundsExceeded { field:
//!    ImportCount, .. }`.
//! 7. **`custom_version_count_cap_rejection`** — `count >
//!    MAX_CUSTOM_VERSIONS` produces `BoundsExceeded { field:
//!    CustomVersionCount, .. }`.
//!
//! The cap-rejection trio (4, 6, 7) sweeps the `BoundsExceeded` arm of
//! every `read_from` that bounds-checks an `i32 count` header; the
//! per-module unit tests pin a single just-over-the-cap value, the
//! proptest sweeps the full `MAX + 1..MAX + 1024` band.
//!
//! Lives in `paksmith-core-tests` (not `paksmith-core/tests/`) because
//! the round-trip arms need `write_to` methods — those are gated
//! behind the `__test_utils` feature, which only this sibling crate
//! activates. (`paksmith-core` deliberately doesn't self-import to
//! avoid a release-please dep-graph cycle; see this crate's
//! `Cargo.toml`.)

#![allow(missing_docs)]

use std::io::Cursor;

use paksmith_core::asset::custom_version::{CustomVersion, CustomVersionContainer};
use paksmith_core::asset::engine_version::EngineVersion;
use paksmith_core::asset::guid::FGuid;
use paksmith_core::asset::import_table::{ImportTable, ObjectImport};
use paksmith_core::asset::name_table::{FName, NameTable};
use paksmith_core::asset::package_index::PackageIndex;
use paksmith_core::asset::version::AssetVersion;
use paksmith_core::error::{AssetParseFault, AssetWireField, PaksmithError};
use proptest::prelude::*;

// Mirrors the private structural caps in
// `asset/{name_table,import_table,custom_version}.rs`. Hard-coded
// rather than re-exported because these are defensive constants — the
// per-module `read_from` unit tests (each module has a
// `rejects_count_over_cap` test that uses `MAX_* + 1`) catch any
// drift before this proptest's "over-cap" arm starts shrinking to
// false positives.
const MAX_NAME_TABLE_ENTRIES: u32 = 1_048_576;
const MAX_IMPORT_TABLE_ENTRIES: u32 = 524_288;
const MAX_CUSTOM_VERSIONS: u32 = 1024;

prop_compose! {
    fn arb_engine_version()(
        major in any::<u16>(),
        minor in any::<u16>(),
        patch in any::<u16>(),
        changelist in any::<u32>(),
        branch in "[a-zA-Z0-9+\\-_.]{0,32}",
    ) -> EngineVersion {
        EngineVersion {
            major,
            minor,
            patch,
            changelist,
            branch,
        }
    }
}

prop_compose! {
    /// UE4.27 baseline — no UE5 trailer fields, so
    /// `ObjectImport::import_optional` round-trips as `None` and the
    /// record is the stable 28-byte form. Licensee version is
    /// randomised: it doesn't currently branch any parsing logic, but
    /// the strategy keeps future licensee-conditional code paths
    /// honest without retrofitting.
    fn arb_ue4_27_version()(licensee in any::<i32>()) -> AssetVersion {
        AssetVersion {
            legacy_file_version: -7,
            file_version_ue4: 522,
            file_version_ue5: None,
            file_version_licensee_ue4: licensee,
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// `EngineVersion` write_to → read_from is the identity.
    #[test]
    fn engine_version_round_trip(v in arb_engine_version()) {
        let mut buf = Vec::new();
        v.write_to(&mut buf).unwrap();
        let parsed = EngineVersion::read_from(
            &mut Cursor::new(&buf),
            "x.uasset",
        )
        .unwrap();
        prop_assert_eq!(parsed, v);
    }

    /// `CustomVersionContainer` write_to → read_from is the identity
    /// over 0..16 random rows. Empty container hits the
    /// `count_u32 == 0` boundary (skips the reserve + read loop).
    #[test]
    fn custom_version_container_round_trip(
        rows in proptest::collection::vec(
            (any::<[u8; 16]>(), any::<i32>()),
            0..16,
        ),
    ) {
        let c = CustomVersionContainer {
            versions: rows
                .into_iter()
                .map(|(g, version)| CustomVersion {
                    guid: FGuid::from_bytes(g),
                    version,
                })
                .collect(),
        };
        let mut buf = Vec::new();
        c.write_to(&mut buf).unwrap();
        let parsed = CustomVersionContainer::read_from(
            &mut Cursor::new(&buf),
            "x.uasset",
        )
        .unwrap();
        prop_assert_eq!(parsed, c);
    }

    /// `NameTable` write_to → read_from is the identity over 0..32
    /// ASCII-identifier-shaped names. The regex keeps names UTF-8 +
    /// no-null + no FString-length-overflow so the round-trip stays
    /// in the happy path; FString-malformed coverage lives in the
    /// hand-written unit tests.
    #[test]
    fn name_table_round_trip(
        names in proptest::collection::vec(
            "[a-zA-Z][a-zA-Z0-9_]{0,15}",
            0..32,
        ),
    ) {
        let table = NameTable {
            names: names.iter().map(|s| FName::new(s)).collect(),
        };
        let mut buf = Vec::new();
        table.write_to(&mut buf).unwrap();
        let count = i32::try_from(table.names.len()).unwrap();
        let parsed = NameTable::read_from(
            &mut Cursor::new(&buf),
            0,
            count,
            "x.uasset",
        )
        .unwrap();
        prop_assert_eq!(parsed, table);
    }

    /// `NameTable::read_from` rejects any `count > MAX_NAME_TABLE_ENTRIES`.
    /// Sweeps the `MAX + 1..MAX + 1024` band against the hand-written
    /// unit test that only pins `MAX + 1`.
    #[test]
    fn name_table_rejects_count_over_cap(over in 1u32..1024) {
        let count = (i64::from(MAX_NAME_TABLE_ENTRIES) + i64::from(over)) as i32;
        let err = NameTable::read_from(
            &mut Cursor::new(Vec::<u8>::new()),
            0,
            count,
            "x.uasset",
        )
        .unwrap_err();
        // Pass an explicit format-string as the second arg to
        // `prop_assert!` so the `{` braces in the `matches!` pattern
        // aren't parsed as format holes. Borrow `err` so it stays live
        // for the diagnostic interpolation.
        prop_assert!(
            matches!(&err, PaksmithError::AssetParse {
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::NameCount,
                    ..
                },
                ..
            }),
            "expected NameCount BoundsExceeded, got: {err:?}"
        );
    }

    /// `ImportTable` write_to → read_from is the identity for the
    /// UE4.27 record shape (no `import_optional` tail). Imports use
    /// raw name indices `i, i+1, i+2` — the parser doesn't
    /// validate name-table membership at table-read time (resolution
    /// is per-element at render time), so any `u32` value round-trips.
    #[test]
    fn import_table_round_trip(
        count in 0u32..8,
        v in arb_ue4_27_version(),
    ) {
        let table = ImportTable {
            imports: (0..count)
                .map(|i| ObjectImport {
                    class_package_name: i,
                    class_package_number: 0,
                    class_name: i + 1,
                    class_name_number: 0,
                    outer_index: PackageIndex::Null,
                    object_name: i + 2,
                    object_name_number: 0,
                    import_optional: None,
                })
                .collect(),
        };
        let mut buf = Vec::new();
        table.write_to(&mut buf, v).unwrap();
        let parsed = ImportTable::read_from(
            &mut Cursor::new(buf),
            0,
            count as i32,
            v,
            "x.uasset",
        )
        .unwrap();
        prop_assert_eq!(parsed, table);
    }

    /// `ImportTable::read_from` rejects any `count >
    /// MAX_IMPORT_TABLE_ENTRIES`. Same coverage rationale as
    /// `name_table_rejects_count_over_cap`.
    #[test]
    fn import_count_cap_rejection(
        over in 1u32..1024,
        v in arb_ue4_27_version(),
    ) {
        let count = (i64::from(MAX_IMPORT_TABLE_ENTRIES) + i64::from(over)) as i32;
        let err = ImportTable::read_from(
            &mut Cursor::new(Vec::<u8>::new()),
            0,
            count,
            v,
            "x.uasset",
        )
        .unwrap_err();
        prop_assert!(
            matches!(&err, PaksmithError::AssetParse {
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::ImportCount,
                    ..
                },
                ..
            }),
            "expected ImportCount BoundsExceeded, got: {err:?}"
        );
    }

    /// `CustomVersionContainer::read_from` rejects any `count >
    /// MAX_CUSTOM_VERSIONS`. Plants a wire-format prefix (just the
    /// `i32 count`) rather than constructing via `write_to` — the
    /// writer caps at `self.versions.len()`, which can't exceed
    /// `usize::MAX` but also can't represent a value > cap without a
    /// `Vec` allocation of that size. Direct byte-planting is both
    /// faster and the exact mirror of how malformed inputs arrive
    /// from a real archive.
    #[test]
    fn custom_version_count_cap_rejection(over in 1u32..1024) {
        let count = MAX_CUSTOM_VERSIONS + over;
        let mut buf = Vec::new();
        buf.extend_from_slice(&(count as i32).to_le_bytes());
        let err = CustomVersionContainer::read_from(
            &mut Cursor::new(&buf),
            "x.uasset",
        )
        .unwrap_err();
        prop_assert!(
            matches!(&err, PaksmithError::AssetParse {
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::CustomVersionCount,
                    ..
                },
                ..
            }),
            "expected CustomVersionCount BoundsExceeded, got: {err:?}"
        );
    }
}
