# Material formats

Material graphs are conceptually large but their on-disk presence in cooked
content is mostly just shader-map references and parameter overrides — the
actual shader code lives in DDC / shader cache, which is out of paksmith's
extraction scope.

- **`material.md`** — `Material` record and shader-map references.
- **`material-instance.md`** — `MaterialInstance` parameter overrides and
  the inheritance chain back to the parent material.
- **`static-parameter-set.md`** — `FStaticParameterSet` wire layout: the
  4-array static-permutation parameter bundle (switches, RGBA component
  masks, terrain layer weights, material layers) plus the shared
  `FMaterialParameterInfo` prefix.
- **`parameter-values.md`** — per-entry value structs
  (`FTextureParameterValue`, `FScalarParameterValue`,
  `FVectorParameterValue`) used in the tagged-property override arrays
  on `UMaterialInstanceConstant`.
