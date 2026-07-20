# Provenance — Vendored Encrypted Pak Fixtures

The following files are **vendored-static** fixtures: committed directly to this
repository and excluded from the CI `rm + regenerate` cycle.

## Files

- `real_v8b_encrypted_entries.pak` (14115 bytes)
- `real_v8b_encrypted_index.pak` (14100 bytes)
- `real_v8b_encrypted_both.pak` (14129 bytes)
- `real_v11_encrypted_index.pak` (14132 bytes)
- `real_v8b_encrypted_compressed.pak` (9315 bytes) — issue #634
- `real_v11_encrypted_compressed.pak` (9674 bytes) — issue #634

## Origin

These are byte-identical copies of `pack_v8b_encrypt*.pak` (and, for the
`_encrypted_compressed` pair, `pack_v8b_compress_encrypt.pak` /
`pack_v11_compress_encrypt.pak`) from the
[trumank/repak](https://github.com/trumank/repak) test suite, licensed under
MIT OR Apache-2.0. They were originally produced by UnrealPak (Unreal Engine's
pak packaging tool) and are used by repak's own test suite to validate
encrypted-pak reading.

Source commit: e215472c51db69328b1ce77be2db24d24c1d646b

Copyright notice (MIT): Copyright 2024 Truman Kilen, spuds

repak's writer (at the pinned SHA) does not support writing encrypted paks
(`Pak::write` hardcodes `encrypted: false`), so procedural regeneration is not
possible. These files are kept as committed binaries.

## Decryption Key

All four fixtures use the same AES-256 key:

- Base64: `lNJbw660IOC+kU7cnVQ1oeqrXyhk4J6UAZrCBbcnp94=`
- Hex: `94d25bc3aeb420e0be914edc9d5435a1eaab5f2864e09e94019ac205b727a7de`

The key is also available as `paksmith_fixture_gen::encryption::FIXTURE_AES_KEY`.

## Contents

The v8b fixtures share the same mount point (`../mount/point/root/`) and the
same four entries: `test.txt`, `directory/nested.txt`, `zeros.bin`, `test.png`.
They differ only in which layers are encrypted (entry data, index, or both).

`real_v11_encrypted_index.pak` is a v11 (Fnv64BugFix) pak with an encrypted
index. It is used to verify that paksmith returns an honest `UnsupportedFeature`
error (not `Decryption`) when attempting to open a v10+ encrypted-index pak —
the path-hash index layout is not yet supported for index decryption. Its entry
list is not verified by paksmith tests (the index cannot be decrypted at this
phase); provenance only is recorded here.

The `_encrypted_compressed` pair (issue #634) carries the same four-entry
corpus with entries that are BOTH zlib-compressed AND AES-256-ECB encrypted
(plaintext indexes: legacy v8b and encoded v11 respectively). They are the
empirical anchors for two wire facts: the stored entry SHA-1 covers the
on-disk ciphertext truncated to `compressed_size`, and — for encrypted
entries — UnrealPak stores `compressed_size` as the sum of the AES-aligned
per-block footprints (v11 `test.png`: claimed 7760 vs unaligned block sum
7746).

## License

MIT OR Apache-2.0 (inherited from trumank/repak).
