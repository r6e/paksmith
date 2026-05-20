# Asset formats

Files that encode one UE package — the unit of `UObject` serialization. A
package always lives across at least one file (`.uasset`) and often two or
three (`.uexp`, `.ubulk`).

- **`.uasset`** — header, name table, import/export tables, optional
  inlined export bodies for older versions.
- **`.uexp`** — export bodies split out from the header for newer versions
  (UE 4.16+ by default).
- **`.ubulk`** — bulk-data payloads (large texture mips, audio bodies)
  streamed separately from the main package.

`companion-resolution.md` documents how paksmith locates the `.uexp` and
`.ubulk` companions given a `.uasset` path.
