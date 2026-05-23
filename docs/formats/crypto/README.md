# Cryptography

Encryption schemes UE uses on cooked content.

- **`aes-pak.md`** — AES-256 ECB encryption for `.pak` index and per-entry
  encryption (UE 4.4+). Documents the key distribution path, the
  `Crypto.json` file format the cooker emits, and paksmith's handling of
  missing keys (uniform refusal across all sites — see aes-pak.md for
  per-site details).

IoStore encryption shares the same AES-256 ECB primitive but applies it
at a different granularity; that will be covered in
`../container/iostore-utoc.md` when the IoStore doc lands.
