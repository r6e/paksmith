# Primitive types

The smallest reusable record shapes that every UE format builds on.
Everything in `container/`, `asset/`, and `property/` references these.

- **`FString`** — variable-length string with a sign-encoded length prefix
  (positive = ASCII, negative = UTF-16, always NUL-terminated).
- **`FName`** — an index + suffix number resolved against a per-package
  name table.
- **`FGuid`** — 128-bit identifier, two endianness conventions in the wild.
- **`FPackageIndex`** — signed index into the package's import or export
  table (positive = export, negative = import, zero = null).
- **`FCustomVersion`** — per-engine-feature version tag carried in the
  package summary.
- **`FEngineVersion`** — major/minor/patch/build/branch record, present in
  some headers.
