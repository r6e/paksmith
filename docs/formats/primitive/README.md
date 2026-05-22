# Primitive types

The smallest reusable record shapes that every UE format builds on.
Everything in `container/`, `asset/`, and `property/` references these.

- **`FString`** — variable-length string with a sign-encoded length prefix
  (positive = UTF-8, negative = UTF-16, always NUL-terminated).
- **`FName`** — an index + suffix number resolved against a per-package
  name table.
- **`FGuid`** — 128-bit identifier stored as four little-endian u32s.
- **`FPackageIndex`** — signed index into the package's import or export
  table (positive = export, negative = import, zero = null).
- **`FCustomVersion`** — per-plugin version stamp carried in the package
  summary.
- **`FEngineVersion`** — major/minor/patch/changelist/branch record,
  present in package summary compatibility metadata.
