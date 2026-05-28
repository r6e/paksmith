//! Phase 3b Task 7 — closes the architect's deferred Finding 2
//! from Task 6's review: `Package::read_from_pak`'s `bulk_data` +
//! `resolver` fields had no integration-test coverage at the
//! out-of-crate boundary.
//!
//! Tests in this file:
//! 1. Pin that `read_from_pak` constructs the resolver with empty
//!    `bulk_data` (the 3e/3g/3h sub-phases will drive population
//!    via their typed readers).
//! 2. Exercise `Package::resolve_bulk_for_export` end-to-end across
//!    all four storage tiers (Inline / UexpResident / Streaming /
//!    OptionalStreaming) using hand-built `FByteBulkData` records
//!    threaded through `insert_bulk_records_for_test`. The unit-
//!    level tier dispatch is covered in `bulk_data.rs`; these tests
//!    focus on the `read_from_pak` -> wired-resolver -> resolve
//!    chain across the crate boundary.
//! 3. The streaming-tier-with-missing-companion path. The lazy
//!    loaders inside `Package::read_from_pak` map `EntryNotFound`
//!    from the pak layer to typed `MissingCompanionFile`; pinned
//!    here against a fixture that explicitly carries no `.ubulk`.
//!
//! Required feature: `__test_utils` (gated by
//! `Package::insert_bulk_records_for_test`,
//! `FByteBulkData::for_test`, and the shared
//! `testing::bulk_data::BULK_COMPANION_SENTINEL`).

use paksmith_core::Package;
use paksmith_core::asset::bulk_data::{BulkDataFlags, BulkDataTier, FByteBulkData};
use paksmith_core::error::{AssetParseFault, CompanionFileKind};
use paksmith_core::testing::bulk_data::BULK_COMPANION_SENTINEL;
use paksmith_core::{BulkData, PaksmithError};

fn fixture_path(name: &str) -> std::path::PathBuf {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join("../../tests/fixtures").join(name)
}

/// Flag bits used by the resolver's tier dispatch. Reproduced here
/// from `bulk_data.rs`'s private `FLAG_*` constants — not exposed
/// at the public API surface. Comments anchor the bit value
/// against the wire-format spec; cross-validated against
/// `docs/formats/asset/bulk-data.md`.
mod flag_bits {
    /// `BULKDATA_PayloadAtEndOfFile` (bit 0): Inline or UexpResident
    /// tier discriminator when `PayloadInSeparateFile` is unset.
    pub const PAYLOAD_AT_END_OF_FILE: u32 = 0x0000_0001;
    /// `BULKDATA_PayloadInSeparateFile` (bit 8): Streaming tier
    /// (`.ubulk`) when `OptionalPayload` is unset; OptionalStreaming
    /// (`.uptnl`) when set.
    pub const PAYLOAD_IN_SEPARATE_FILE: u32 = 0x0000_0100;
    /// `BULKDATA_OptionalPayload` (bit 11): OptionalStreaming tier
    /// discriminator. Paired with `PayloadInSeparateFile`.
    pub const OPTIONAL_PAYLOAD: u32 = 0x0000_0800;
    /// `BULKDATA_NoOffsetFixUp` (bit 16): tells the resolver NOT to
    /// add `bulk_data_start_offset` to `OffsetInFile`. Set on the
    /// hand-built test records so the offsets we pass through map
    /// directly to fixture positions (the minimal UE 4.27 fixture
    /// has `bulk_data_start_offset == 0` anyway; the explicit flag
    /// makes the test independent of that summary value).
    pub const NO_OFFSET_FIXUP: u32 = 0x0001_0000;
}

#[test]
fn read_from_pak_ubulk_fixture_initializes_empty_resolver() {
    // Confirms the architect's deferred Finding 2 from Task 6's
    // R1 panel: `read_from_pak`'s resolver fields are constructed
    // but `bulk_data` ships empty (Phase 3b is wiring-only; 3e/3g/3h
    // populate via typed readers). The `Arc::ptr_eq` invariant
    // under clone is also pinned via Task 6's in-source test;
    // this exercises the same shape across crate boundaries.
    let pak_path = fixture_path("real_v8b_ubulk.pak");
    let pkg = Package::read_from_pak(&pak_path, "Game/Maps/Demo.uasset", None)
        .expect("real_v8b_ubulk.pak parse");
    // No 3e/3g/3h typed reader registered → no records populated.
    let resolved = pkg
        .resolve_bulk_for_export(0)
        .expect("empty bulk_data → resolve_bulk_for_export Ok(&[])");
    assert!(
        resolved.is_empty(),
        "expected empty BulkData slice; got {} entries",
        resolved.len()
    );
}

#[test]
fn resolve_inline_tier_returns_uasset_body_bytes() {
    // Inline tier (PayloadAtEndOfFile=1, PayloadInSeparateFile=0).
    // `offset_in_file < total_header_size` routes to the `.uasset`
    // body slice. Read the parsed asset's first 8 bytes of the
    // stitched buffer via a synthetic record pointing at offset 0
    // with size_on_disk=8.
    //
    // The minimal v8b fixture's first 8 bytes are the wire-format
    // magic `0x9E2A83C1` (LE) + the next 4 bytes of summary header.
    // We don't pin the exact byte values here — they're version-
    // dependent (UE 4.27 specifically). Instead we pin that the
    // returned slice has the expected length and matches the
    // parsed asset's first 8 bytes byte-for-byte.
    let pak_path = fixture_path("real_v8b_ubulk.pak");

    // Pull the .uasset entry's raw bytes out of the pak so we can
    // assert byte-for-byte equality on what the resolver returns
    // from the inline tier.
    let mut pkg =
        Package::read_from_pak(&pak_path, "Game/Maps/Demo.uasset", None).expect("parse uasset");
    let uasset_bytes = {
        use paksmith_core::container::{ContainerReader, pak::PakReader};
        let reader = PakReader::open(&pak_path).expect("re-open pak");
        reader
            .read_entry("Game/Maps/Demo.uasset")
            .expect("read .uasset entry")
    };

    // Pre-condition: `offset_in_file=0, size_on_disk=8` is Inline
    // tier only when `total_header_size > 8`. The minimal UE 4.27
    // fixture has a header of ~hundreds of bytes (summary + name
    // table + import table + export table), so this is trivially
    // satisfied — but assert the invariant so the test fails LOUDLY
    // if a future fixture refactor ever shrinks the header. Per
    // architect R1 unasked finding.
    assert!(
        pkg.summary.total_header_size > 8,
        "fixture header too small for inline-tier offset test: total_header_size = {}",
        pkg.summary.total_header_size,
    );

    let inline_record = FByteBulkData::for_test(
        BulkDataFlags::from(flag_bits::PAYLOAD_AT_END_OF_FILE | flag_bits::NO_OFFSET_FIXUP),
        8,    // element_count
        8,    // size_on_disk (uncompressed → matches element_count)
        0i64, // offset_in_file → first byte of .uasset body
    );
    pkg.insert_bulk_records_for_test(0, vec![inline_record])
        .expect("insert inline record");
    let bulk = pkg.resolve_bulk_for_export(0).expect("inline resolve");
    assert_eq!(bulk.len(), 1, "exactly one resolved record");
    let BulkData { bytes, tier, .. } = &bulk[0];
    assert_eq!(
        *tier,
        BulkDataTier::Inline,
        "PayloadAtEndOfFile + monolithic .uasset → Inline"
    );
    assert_eq!(bytes.len(), 8, "size_on_disk=8 → 8 resolved bytes");
    assert_eq!(
        bytes.as_slice(),
        &uasset_bytes[..8],
        "inline tier must return the .uasset body slice byte-for-byte"
    );
}

#[test]
fn resolve_uexp_resident_tier_returns_uexp_body_bytes() {
    // UexpResident tier (PayloadAtEndOfFile=1, PayloadInSeparateFile=0,
    // offset_in_file >= total_header_size). The resolver dispatches
    // Inline-vs-UexpResident based on whether the absolute offset
    // falls before or at/after `summary.total_header_size` in the
    // stitched buffer.
    //
    // Uses `real_v8b_split.pak` (the existing Phase 2e fixture):
    // monolithic .uasset header + .uexp companion. The .uexp's
    // first byte sits at `stitched_buffer[total_header_size]`, so
    // an `offset_in_file = total_header_size` record routes to
    // UexpResident. We assert byte-for-byte against the raw .uexp
    // entry bytes.
    let pak_path = fixture_path("real_v8b_split.pak");
    let mut pkg = Package::read_from_pak(&pak_path, "Game/Maps/Demo.uasset", None)
        .expect("parse split asset");
    let uexp_bytes = {
        use paksmith_core::container::{ContainerReader, pak::PakReader};
        let reader = PakReader::open(&pak_path).expect("re-open pak");
        reader
            .read_entry("Game/Maps/Demo.uexp")
            .expect("read .uexp entry")
    };
    assert!(
        uexp_bytes.len() >= 8,
        ".uexp must have at least 8 bytes for the slice equality check; got {}",
        uexp_bytes.len()
    );

    let header_end = i64::from(pkg.summary.total_header_size);
    let uexp_resident_record = FByteBulkData::for_test(
        BulkDataFlags::from(flag_bits::PAYLOAD_AT_END_OF_FILE | flag_bits::NO_OFFSET_FIXUP),
        8,          // element_count
        8,          // size_on_disk
        header_end, // offset_in_file → first byte of .uexp
    );
    pkg.insert_bulk_records_for_test(0, vec![uexp_resident_record])
        .expect("insert uexp-resident record");
    let bulk = pkg
        .resolve_bulk_for_export(0)
        .expect("uexp-resident resolve");
    assert_eq!(bulk.len(), 1);
    let BulkData { bytes, tier, .. } = &bulk[0];
    assert_eq!(
        *tier,
        BulkDataTier::UexpResident,
        "PayloadAtEndOfFile + offset >= total_header_size → UexpResident"
    );
    assert_eq!(
        bytes.as_slice(),
        &uexp_bytes[..8],
        "UexpResident tier must return the .uexp body slice byte-for-byte"
    );
}

#[test]
fn resolve_streaming_tier_returns_ubulk_sentinel_bytes() {
    // Streaming tier (PayloadInSeparateFile=1, OptionalPayload=0).
    // `read_from_pak` baked an `.ubulk` loader closure capturing
    // an `Arc<PakReader>`; first matching-tier resolve fires the
    // closure, loads `Game/Maps/Demo.ubulk`, and the OnceLock
    // caches it.
    //
    // The fixture's `.ubulk` is exactly `BULK_COMPANION_SENTINEL` — 32
    // ascending bytes. With offset_in_file=0 and size_on_disk=32,
    // the resolver must return the full sentinel.
    let pak_path = fixture_path("real_v8b_ubulk.pak");
    let mut pkg =
        Package::read_from_pak(&pak_path, "Game/Maps/Demo.uasset", None).expect("parse uasset");
    let streaming_record = FByteBulkData::for_test(
        BulkDataFlags::from(flag_bits::PAYLOAD_IN_SEPARATE_FILE | flag_bits::NO_OFFSET_FIXUP),
        32,   // element_count
        32,   // size_on_disk
        0i64, // offset_in_file → start of .ubulk
    );
    pkg.insert_bulk_records_for_test(0, vec![streaming_record])
        .expect("insert streaming record");
    let bulk = pkg.resolve_bulk_for_export(0).expect("streaming resolve");
    assert_eq!(bulk.len(), 1);
    let BulkData { bytes, tier, .. } = &bulk[0];
    assert_eq!(*tier, BulkDataTier::Streaming);
    assert_eq!(
        bytes.as_slice(),
        BULK_COMPANION_SENTINEL,
        ".ubulk sentinel must round-trip byte-for-byte through resolver"
    );
}

#[test]
fn resolve_optional_streaming_tier_returns_uptnl_sentinel_bytes() {
    // OptionalStreaming tier (PayloadInSeparateFile=1 AND
    // OptionalPayload=1). Mirror of the streaming-tier test for
    // the `.uptnl` companion path. Uses the `real_v8b_uptnl.pak`
    // fixture (sentinel bytes in `.uptnl`, NOT `.ubulk`); the
    // resolver's `uptnl_loader` closure fires and returns them.
    let pak_path = fixture_path("real_v8b_uptnl.pak");
    let mut pkg =
        Package::read_from_pak(&pak_path, "Game/Maps/Demo.uasset", None).expect("parse uasset");
    let optional_record = FByteBulkData::for_test(
        BulkDataFlags::from(
            flag_bits::PAYLOAD_IN_SEPARATE_FILE
                | flag_bits::OPTIONAL_PAYLOAD
                | flag_bits::NO_OFFSET_FIXUP,
        ),
        32,
        32,
        0i64,
    );
    pkg.insert_bulk_records_for_test(0, vec![optional_record])
        .expect("insert optional record");
    let bulk = pkg
        .resolve_bulk_for_export(0)
        .expect("optional streaming resolve");
    assert_eq!(bulk.len(), 1);
    let BulkData { bytes, tier, .. } = &bulk[0];
    assert_eq!(*tier, BulkDataTier::OptionalStreaming);
    assert_eq!(
        bytes.as_slice(),
        BULK_COMPANION_SENTINEL,
        ".uptnl sentinel must round-trip byte-for-byte through resolver"
    );
}

#[test]
fn missing_ubulk_for_streaming_record_fires_typed_companion_error() {
    // Streaming-tier record with NO `.ubulk` in the pak. The
    // existing `real_v8b_uasset.pak` fixture is a monolithic
    // .uasset only — no companion. The resolver's lazy loader
    // calls into `PakReader::read_entry("Game/Maps/Demo.ubulk")`
    // which returns `EntryNotFound`, mapped to typed
    // `MissingCompanionFile { kind: Ubulk }` per the closure body
    // in `Package::read_from_pak`.
    let pak_path = fixture_path("real_v8b_uasset.pak");
    let mut pkg = Package::read_from_pak(&pak_path, "Game/Maps/Demo.uasset", None)
        .expect("parse monolithic uasset");
    let streaming_record = FByteBulkData::for_test(
        BulkDataFlags::from(flag_bits::PAYLOAD_IN_SEPARATE_FILE | flag_bits::NO_OFFSET_FIXUP),
        16,
        16,
        0i64,
    );
    pkg.insert_bulk_records_for_test(0, vec![streaming_record])
        .expect("insert streaming record");
    let err = pkg
        .resolve_bulk_for_export(0)
        .expect_err("streaming-tier record without .ubulk must error");
    match err {
        PaksmithError::AssetParse {
            fault:
                AssetParseFault::MissingCompanionFile {
                    kind: CompanionFileKind::Ubulk,
                },
            asset_path,
        } => {
            assert_eq!(
                asset_path, "Game/Maps/Demo.uasset",
                "MissingCompanionFile must carry the asset_path the resolver was called with"
            );
        }
        other => panic!("expected MissingCompanionFile(Ubulk), got {other:?}"),
    }
}

#[test]
fn missing_uptnl_for_optional_streaming_record_fires_typed_companion_error() {
    // Mirror of the previous test for the `.uptnl` lazy loader.
    // `real_v8b_ubulk.pak` carries a `.ubulk` but no `.uptnl`,
    // so an OptionalStreaming-tier record must surface
    // `MissingCompanionFile { kind: Uptnl }`.
    let pak_path = fixture_path("real_v8b_ubulk.pak");
    let mut pkg =
        Package::read_from_pak(&pak_path, "Game/Maps/Demo.uasset", None).expect("parse uasset");
    let optional_record = FByteBulkData::for_test(
        BulkDataFlags::from(
            flag_bits::PAYLOAD_IN_SEPARATE_FILE
                | flag_bits::OPTIONAL_PAYLOAD
                | flag_bits::NO_OFFSET_FIXUP,
        ),
        16,
        16,
        0i64,
    );
    pkg.insert_bulk_records_for_test(0, vec![optional_record])
        .expect("insert optional record");
    let err = pkg
        .resolve_bulk_for_export(0)
        .expect_err("optional-streaming record without .uptnl must error");
    assert!(
        matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::MissingCompanionFile {
                    kind: CompanionFileKind::Uptnl,
                },
                ..
            }
        ),
        "expected MissingCompanionFile(Uptnl), got {err:?}"
    );
}

#[test]
fn resolve_caches_after_first_call() {
    // OnceLock cache pin: the second `resolve_bulk_for_export`
    // call on the same export_idx must return a slice over the
    // same backing Vec as the first call. Tests the lazy-cache
    // path end-to-end across the pak boundary.
    let pak_path = fixture_path("real_v8b_ubulk.pak");
    let mut pkg =
        Package::read_from_pak(&pak_path, "Game/Maps/Demo.uasset", None).expect("parse uasset");
    let record = FByteBulkData::for_test(
        BulkDataFlags::from(flag_bits::PAYLOAD_IN_SEPARATE_FILE | flag_bits::NO_OFFSET_FIXUP),
        32,
        32,
        0i64,
    );
    pkg.insert_bulk_records_for_test(0, vec![record])
        .expect("insert");
    let first = pkg.resolve_bulk_for_export(0).expect("first resolve");
    let first_ptr = first.as_ptr();
    let second = pkg.resolve_bulk_for_export(0).expect("second resolve");
    assert!(
        std::ptr::eq(first_ptr, second.as_ptr()),
        "second call must return the same OnceLock-cached slice (no re-resolve, no re-allocate)"
    );
}
