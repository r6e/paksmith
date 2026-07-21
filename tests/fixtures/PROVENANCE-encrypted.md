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

All six fixtures use the same AES-256 key:

- Base64: `lNJbw660IOC+kU7cnVQ1oeqrXyhk4J6UAZrCBbcnp94=`
- Hex: `94d25bc3aeb420e0be914edc9d5435a1eaab5f2864e09e94019ac205b727a7de`

The key is also available as `paksmith_fixture_gen::encryption::FIXTURE_AES_KEY`.

## Contents

The v8b fixtures share the same mount point (`../mount/point/root/`) and the
same four entries: `test.txt`, `directory/nested.txt`, `zeros.bin`, `test.png`.
They differ only in which layers are encrypted (entry data, index, or both).

`real_v11_encrypted_index.pak` is a v11 (Fnv64BugFix) pak with an encrypted
index. Since #635 paksmith decrypts the v10/v11 path-hash index — all three
regions (primary, path-hash, and full-directory) are AES-256-ECB encrypted in
place and 16-aligned on disk, and each stores the SHA-1 of its plaintext (the
opposite of the per-entry ciphertext convention, so index verification requires
the key). This fixture anchors the v10+ encrypted-index tests: with the correct
key paksmith opens it, lists its entries, reads a file, and verifies its index
hash; a wrong key fails closed as `Decryption`. The v10 half of that coverage
patches this fixture's footer version u32 (11→10) in-memory — v10/v11 share an
identical footer and index wire layout, and `fnv64_path` is version-agnostic.

The `_encrypted_compressed` pair (issue #634) carries the same four-entry
corpus, AES-256-ECB encrypted, behind plaintext indexes (legacy v8b and
encoded v11 respectively). In the v8b fixture all four entries are
zlib-compressed; in the v11 fixture only `test.png` and `zeros.bin` are
compressed while `test.txt`/`nested.txt` are stored uncompressed (the two
text entries do compress — ~40% in the v8b sibling — so UnrealPak's v11
packaging left them uncompressed by a packaging choice, not because they
are incompressible). They are the
empirical anchors for two wire facts: the stored entry SHA-1 covers the
on-disk ciphertext truncated to `compressed_size`, and — for encrypted
entries — UnrealPak stores `compressed_size` as the sum of the AES-aligned
per-block footprints (v11 `test.png`: claimed 7760 vs unaligned block sum
7746).

## License

MIT OR Apache-2.0 (inherited from trumank/repak).
