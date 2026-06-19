# Provenance — Vendored Encrypted Pak Fixtures

The following files are **vendored-static** fixtures: committed directly to this
repository and excluded from the CI `rm + regenerate` cycle.

## Files

- `real_v8b_encrypted_entries.pak` (14115 bytes)
- `real_v8b_encrypted_index.pak` (14100 bytes)
- `real_v8b_encrypted_both.pak` (14129 bytes)

## Origin

These are byte-identical copies of `pack_v8b_encrypt*.pak` from the
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

All three fixtures use the same AES-256 key:

- Base64: `lNJbw660IOC+kU7cnVQ1oeqrXyhk4J6UAZrCBbcnp94=`
- Hex: `94d25bc3aeb420e0be914edc9d5435a1eaab5f2864e09e94019ac205b727a7de`

The key is also available as `paksmith_fixture_gen::encryption::FIXTURE_AES_KEY`.

## Contents

All three fixtures share the same mount point (`../mount/point/root/`) and the
same four entries: `test.txt`, `directory/nested.txt`, `zeros.bin`, `test.png`.
The fixtures differ only in which layers are encrypted (entry data, index, or both).

## License

MIT OR Apache-2.0 (inherited from trumank/repak).
