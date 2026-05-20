# Material formats

Material graphs are conceptually large but their on-disk presence in cooked
content is mostly just shader-map references and parameter overrides — the
actual shader code lives in DDC / shader cache, which is out of paksmith's
extraction scope.

- **`material.md`** — `Material` record and shader-map references.
- **`material-instance.md`** — `MaterialInstance` parameter overrides and
  the inheritance chain back to the parent material.
