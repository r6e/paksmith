# Container formats

Archive formats that hold cooked UE content on disk. A paksmith run starts
here — the container reader yields entries, which the asset layer then
deserializes.

Two top-level formats are in scope:

- **`.pak`** — the legacy archive format. One file. Eleven on-disk versions
  (V1 through V11) covering UE 4.0 through UE 5.x. Paksmith's primary
  container today.
- **IoStore** (`.utoc` + `.ucas` + optional `.uptnl`) — UE4.27+ replacement
  for `.pak` aimed at faster shipped-game IO. Three coupled files per
  container.

Encryption, compression, and on-disk integrity are documented separately:
see `../crypto/README.md` and `../compression/README.md`.
