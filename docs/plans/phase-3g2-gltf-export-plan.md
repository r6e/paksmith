# Phase 3g2 — `GltfStaticMeshHandler` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Design/spec: [`phase-3g2-gltf-export.md`](phase-3g2-gltf-export.md).

**Goal:** Add a `FormatHandler` that lowers a parsed cooked `UStaticMesh` (`StaticMeshData` → `StaticMeshRenderData` → `StaticMeshLod`) into a single self-contained glTF 2.0 binary (`.glb`) that opens upright, metre-scaled, and correctly-wound in Blender, with per-section material slots.

**Architecture:** A new `crates/paksmith-core/src/export/static_mesh.rs` module holds `GltfStaticMeshHandler` plus an internal `GltfDoc` accumulator that owns the growing BIN buffer and the `gltf_json::Root`, exposing a `push_accessor` helper so each attribute lowering is a few concrete lines. Coordinate conversion is isolated, pure functions. The handler is registered in `HandlerRegistry::all_default_handlers()` under the `StaticMesh` discriminant.

**Tech Stack:** Rust, the `gltf` crate (`gltf::json` schema types + `gltf::binary::Glb` GLB container), `serde_json::Value` (already a workspace dep) for accessor `min`/`max`.

---

## File structure

- **Create** `crates/paksmith-core/src/export/static_mesh.rs` — `GltfStaticMeshHandler`, the `GltfDoc` accumulator + `push_accessor`, the coordinate-conversion functions, per-attribute / per-section / per-LOD lowering, and all unit + integration tests.
- **Modify** `Cargo.toml` (workspace root) — add `gltf` to `[workspace.dependencies]`.
- **Modify** `crates/paksmith-core/Cargo.toml` — depend on `gltf`.
- **Modify** `crates/paksmith-core/src/export/mod.rs` — `mod static_mesh;`, re-export `GltfStaticMeshHandler`, register it in `all_default_handlers()`.
- **Reference (read-only):** `crates/paksmith-core/src/export/texture.rs` (handler precedent), `crates/paksmith-core/src/asset/mod.rs` (`StaticMeshData`/`StaticMeshRenderData`/`StaticMeshLod`/`MeshSection` field shapes), `crates/paksmith-core/src/asset/structs/vector.rs` (`FVector`/`FVector2D`/`FVector4` fields), `crates/paksmith-core/src/asset/structs/color.rs` (`FColor`).

All work happens in the worktree `.claude/worktrees/feat+phase-3g2-gltf-export/` (branch `feat/phase-3g2-gltf-export`). Run every command from there.

---

## Task 1: Add the `gltf` dependency and pin the write API

**Files:**
- Modify: `Cargo.toml` (workspace `[workspace.dependencies]`)
- Modify: `crates/paksmith-core/Cargo.toml` (`[dependencies]`)
- Create: `crates/paksmith-core/src/export/static_mesh.rs` (spike test only, for now)
- Modify: `crates/paksmith-core/src/export/mod.rs` (add `mod static_mesh;`)

- [ ] **Step 1: Verify the crate's current version + write surface on docs.rs**

Open <https://docs.rs/gltf/latest/gltf/binary/struct.Glb.html> and <https://docs.rs/gltf-json/latest/gltf_json/struct.Root.html>. Confirm `gltf::binary::Glb { header, json: Cow<[u8]>, bin: Option<Cow<[u8]>> }` with `fn to_vec(&self) -> Result<Vec<u8>, Error>`, and `gltf::json::Root` is `serde::Serialize`. Note the latest `1.x` version for the Cargo entry.

- [ ] **Step 2: Add the dependency**

In the workspace root `Cargo.toml` under `[workspace.dependencies]` (keep the list alphabetically ordered to match the existing style):

```toml
gltf = { version = "1.4", default-features = false, features = ["names"] }
```

In `crates/paksmith-core/Cargo.toml` under `[dependencies]`:

```toml
gltf.workspace = true
```

Rationale: `default-features = false` drops the `import`/`utils` reader machinery; `names` enables the `name` fields on nodes/materials/meshes (the spec wants `LOD0`..`LODn` + per-slot material names). The `json` and `binary` modules are needed for writing.

- [ ] **Step 3: Write the API-pinning spike test**

Create `crates/paksmith-core/src/export/static_mesh.rs` with ONLY this (the real handler arrives in Task 2):

```rust
//! `UStaticMesh` → glTF 2.0 (`.glb`) export — Phase 3g2.
//!
//! Lowers parsed [`crate::asset::StaticMeshData`] render geometry into a
//! self-contained binary glTF. Design: `docs/plans/phase-3g2-gltf-export.md`.

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    /// Pin the `gltf` write API: an empty `json::Root` (asset only) serializes,
    /// wraps in a `binary::Glb`, and `to_vec` produces bytes starting with the
    /// `glTF` magic. Establishes the exact types the later tasks build on.
    #[test]
    fn gltf_write_api_round_trips_empty_doc() {
        let root = gltf::json::Root::default();
        let json = serde_json::to_vec(&root).expect("serialize root");
        // GLB JSON chunk must be 4-byte aligned (pad with spaces, 0x20).
        let mut json = json;
        while json.len() % 4 != 0 {
            json.push(b' ');
        }
        let glb = gltf::binary::Glb {
            header: gltf::binary::Header {
                magic: *b"glTF",
                version: 2,
                // `to_vec` recomputes the total length; 0 is a safe placeholder.
                length: 0,
            },
            json: Cow::Owned(json),
            bin: None,
        };
        let bytes = glb.to_vec().expect("glb to_vec");
        assert_eq!(&bytes[0..4], b"glTF", "GLB magic");
        assert!(bytes.len() >= 12, "GLB has at least a 12-byte header");
    }
}
```

In `crates/paksmith-core/src/export/mod.rs`, add near the other `mod` declarations:

```rust
mod static_mesh;
```

- [ ] **Step 4: Compile + run the spike; adjust features if needed**

Run: `cargo test -p paksmith-core --all-features export::static_mesh::tests::gltf_write_api`
Expected: PASS. If `gltf::binary` or `gltf::json` is not found, the `binary` module is behind a feature — add `"import"` to the `gltf` features in both Cargo.toml files and re-run. If `gltf::binary::Header` fields differ from the spike, correct the literal to match docs.rs and re-run. Do not proceed until this passes.

- [ ] **Step 5: Run cargo-deny on the new dependency**

Run: `cargo deny check 2>&1 | tail -5`
Expected: `advisories ok, bans ok, licenses ok, sources ok`. If `licenses` flags a transitive dep, add the SPDX id to `[licenses].allow` in `deny.toml`; if `bans` flags a duplicate, document it. `gltf` is MIT/Apache-2.0 — no `allow-git`/`version` dance (it is a crates.io dep, not git).

- [ ] **Step 6: Run typos**

Run: `typos crates/paksmith-core/src/export/static_mesh.rs Cargo.toml`
Expected: no output. Add any flagged technical token to `_typos.toml` if it is a real identifier.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock crates/paksmith-core/Cargo.toml crates/paksmith-core/src/export/static_mesh.rs crates/paksmith-core/src/export/mod.rs deny.toml
git commit -m "build(export): add gltf crate + pin GLB write API (3g2)"
```

---

## Task 2: Handler skeleton — empty valid GLB + registration

**Files:**
- Modify: `crates/paksmith-core/src/export/static_mesh.rs`
- Modify: `crates/paksmith-core/src/export/mod.rs`
- Reference: `crates/paksmith-core/src/export/texture.rs` (the `PngHandler` impl shape), `crates/paksmith-core/src/export/mod.rs` (the `FormatHandler` trait + `all_default_handlers`)

- [ ] **Step 1: Write failing tests for the handler surface**

Add to `static_mesh.rs` (above the existing `mod tests`, replacing the spike module's outer placement — keep the spike test inside `mod tests`):

```rust
use std::borrow::Cow;

use crate::asset::{Asset, StaticMeshData};
use crate::export::{BulkData, FormatHandler};

/// Lowers a cooked `UStaticMesh` into a self-contained glTF 2.0 binary (`.glb`).
/// See `docs/plans/phase-3g2-gltf-export.md`.
#[derive(Debug, Default, Clone, Copy)]
pub struct GltfStaticMeshHandler;

impl FormatHandler for GltfStaticMeshHandler {
    fn output_extension(&self) -> &'static str {
        "glb"
    }

    fn supports(&self, asset: &Asset) -> bool {
        matches!(asset, Asset::StaticMesh(d) if d.render_data.is_some())
    }

    fn export(&self, asset: &Asset, _bulk: &[BulkData]) -> crate::Result<Vec<u8>> {
        let Asset::StaticMesh(data) = asset else {
            return Err(crate::PaksmithError::Internal {
                context: "GltfStaticMeshHandler::export called on a non-StaticMesh Asset"
                    .to_string(),
            });
        };
        let render = data.render_data.as_ref().ok_or_else(|| crate::PaksmithError::Internal {
            context: "GltfStaticMeshHandler::export called on a StaticMesh with no render data"
                .to_string(),
        })?;
        let _ = render;
        // Minimal valid glTF: asset + one empty scene set as the default scene.
        let mut root = gltf::json::Root::default();
        let scene = root.push(gltf::json::Scene {
            extensions: Default::default(),
            extras: Default::default(),
            name: None,
            nodes: Vec::new(),
        });
        root.scene = Some(scene);
        finish_glb(root, Vec::new())
    }
}

/// Serialize `root` + the BIN `buffer` into GLB bytes. The JSON chunk is padded
/// to a 4-byte boundary with spaces and the BIN chunk to a 4-byte boundary with
/// zeros, per the GLB spec; `Glb::to_vec` writes the chunk framing + recomputes
/// the total length.
fn finish_glb(root: gltf::json::Root, mut bin: Vec<u8>) -> crate::Result<Vec<u8>> {
    let mut json = serde_json::to_vec(&root).map_err(|e| crate::PaksmithError::Internal {
        context: format!("glTF JSON serialization failed: {e}"),
    })?;
    while json.len() % 4 != 0 {
        json.push(b' ');
    }
    while bin.len() % 4 != 0 {
        bin.push(0);
    }
    let bin = if bin.is_empty() { None } else { Some(Cow::Owned(bin)) };
    let glb = gltf::binary::Glb {
        header: gltf::binary::Header { magic: *b"glTF", version: 2, length: 0 },
        json: Cow::Owned(json),
        bin,
    };
    glb.to_vec().map_err(|e| crate::PaksmithError::Internal {
        context: format!("GLB container assembly failed: {e}"),
    })
}
```

In `mod tests`, add:

```rust
    use super::*;
    use crate::asset::{Asset, StaticMeshData, StaticMeshRenderData};
    use crate::asset::structs::bounds::FBoxSphereBounds;
    use crate::asset::structs::vector::FVector;

    /// A cooked StaticMesh whose `render_data` has the given LODs (empty bounds).
    fn mesh_with(render: StaticMeshRenderData) -> Asset {
        let mut data = StaticMeshData::empty();
        data.cooked = true;
        data.render_data = Some(render);
        Asset::StaticMesh(data)
    }

    fn empty_render() -> StaticMeshRenderData {
        StaticMeshRenderData {
            lods: Vec::new(),
            bounds: FBoxSphereBounds {
                origin: FVector { x: 0.0, y: 0.0, z: 0.0 },
                box_extent: FVector { x: 0.0, y: 0.0, z: 0.0 },
                sphere_radius: 0.0,
            },
            lods_share_static_lighting: false,
            screen_sizes: Vec::new(),
        }
    }

    #[test]
    fn extension_is_glb() {
        assert_eq!(GltfStaticMeshHandler.output_extension(), "glb");
    }

    #[test]
    fn supports_cooked_mesh_with_render_data_only() {
        assert!(GltfStaticMeshHandler.supports(&mesh_with(empty_render())));
        // No render data → not supported (parser degrades it to Generic upstream; find_handler returns None).
        assert!(!GltfStaticMeshHandler.supports(&Asset::StaticMesh(StaticMeshData::empty())));
        // Other variants → not supported.
        assert!(!GltfStaticMeshHandler.supports(&Asset::Generic(
            crate::asset::PropertyBag::opaque(Vec::new())
        )));
    }

    #[test]
    fn exports_minimal_valid_glb() {
        let bytes = GltfStaticMeshHandler
            .export(&mesh_with(empty_render()), &[])
            .expect("export");
        assert_eq!(&bytes[0..4], b"glTF");
        // Round-trip with the gltf reader: one scene, zero nodes.
        let glb = gltf::Glb::from_slice(&bytes).expect("parse glb");
        let doc = gltf::json::deserialize::from_slice::<gltf::json::Root>(&glb.json)
            .expect("parse json");
        assert_eq!(doc.scenes.len(), 1);
        assert_eq!(doc.scenes[0].nodes.len(), 0);
    }
```

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test -p paksmith-core --all-features export::static_mesh`
Expected: FAIL — `GltfStaticMeshHandler` / `finish_glb` may already compile, but `gltf::json::deserialize` path or `BulkData`/`FormatHandler` imports may need fixing. If `gltf::json::deserialize::from_slice` is not the right reader call, replace the round-trip in `exports_minimal_valid_glb` with `serde_json::from_slice::<gltf::json::Root>(&glb.json)`.

- [ ] **Step 3: Register the handler**

In `crates/paksmith-core/src/export/mod.rs`, change `mod static_mesh;` to `pub mod static_mesh;` (or add `pub use static_mesh::GltfStaticMeshHandler;` next to the other handler re-exports), and in `all_default_handlers()`, after the audio handler registrations, add:

```rust
    // Phase 3g2: UStaticMesh → glTF (.glb). Sole static-mesh handler.
    let sm_sentinel = Asset::StaticMesh(crate::asset::StaticMeshData::empty());
    reg.register(
        std::mem::discriminant(&sm_sentinel),
        Box::new(static_mesh::GltfStaticMeshHandler),
    );
```

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test -p paksmith-core --all-features export::static_mesh`
Expected: PASS (4 tests: spike + extension + supports + exports_minimal).

- [ ] **Step 5: Add a registry-dispatch test**

In `mod tests`:

```rust
    #[test]
    fn registry_routes_cooked_static_mesh_to_glb() {
        let reg = crate::export::HandlerRegistry::all_default_handlers();
        let asset = mesh_with(empty_render());
        let handler = reg.find_handler(&asset).expect("a handler");
        assert_eq!(handler.output_extension(), "glb");
    }
```

Run: `cargo test -p paksmith-core --all-features export::static_mesh::tests::registry_routes`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/paksmith-core/src/export/static_mesh.rs crates/paksmith-core/src/export/mod.rs
git commit -m "feat(export): GltfStaticMeshHandler skeleton + registration (3g2)"
```

---

## Task 3: `GltfDoc` accumulator + `push_accessor` helper

**Files:**
- Modify: `crates/paksmith-core/src/export/static_mesh.rs`

This centralizes the verbose `gltf_json` plumbing so every later attribute task is a few lines. One BIN buffer; each `push_accessor` appends 4-byte-aligned bytes, creates a `buffer::View` + an `accessor::Accessor`, and returns the accessor `Index`.

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn gltf_doc_push_accessor_aligns_and_indexes() {
        let mut doc = GltfDoc::new();
        // 3 f32 = 12 bytes, already 4-aligned.
        let a = doc.push_accessor(
            &[1.0f32, 2.0, 3.0].iter().flat_map(|f| f.to_le_bytes()).collect::<Vec<u8>>(),
            gltf::json::accessor::ComponentType::F32,
            gltf::json::accessor::Type::Scalar,
            3,
            None,
            None,
            None,
            false,
        );
        // 1 byte → padded to 4 before the next view starts.
        let b = doc.push_accessor(
            &[0xAAu8],
            gltf::json::accessor::ComponentType::U8,
            gltf::json::accessor::Type::Scalar,
            1,
            Some(gltf::json::buffer::Target::ElementArrayBuffer),
            None,
            None,
            false,
        );
        assert_eq!(a.value(), 0);
        assert_eq!(b.value(), 1);
        let (root, bin) = doc.into_parts();
        assert_eq!(root.accessors.len(), 2);
        assert_eq!(root.buffer_views.len(), 2);
        assert_eq!(root.buffers.len(), 1);
        // View 0 at offset 0 (len 12); view 1 starts at 12 (12 already aligned).
        assert_eq!(u64::from(root.buffer_views[1].byte_offset.unwrap()), 12);
        // BIN length is the final 4-aligned total (12 + 1 → padded to 16).
        assert_eq!(bin.len(), 16);
        assert_eq!(u64::from(root.buffers[0].byte_length), 16);
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p paksmith-core --all-features export::static_mesh::tests::gltf_doc_push_accessor`
Expected: FAIL — `GltfDoc` not defined.

- [ ] **Step 3: Implement `GltfDoc`**

Add to `static_mesh.rs`:

```rust
use gltf::json::accessor::{ComponentType, GenericComponentType, Type};
use gltf::json::buffer::Target;
use gltf::json::validation::Checked::Valid;
use gltf::json::validation::USize64;
use gltf::json::Index;

/// Accumulates the single glTF BIN buffer + the `json::Root` under construction.
/// Each `push_accessor` 4-byte-aligns the buffer, emits a `buffer::View` and an
/// `accessor::Accessor`, and returns the accessor index for primitive wiring.
struct GltfDoc {
    root: gltf::json::Root,
    bin: Vec<u8>,
}

impl GltfDoc {
    fn new() -> Self {
        Self { root: gltf::json::Root::default(), bin: Vec::new() }
    }

    /// Append `data` as a new bufferView + accessor. `min`/`max` are the
    /// glTF-required position bounds (or `None`); `target` distinguishes vertex
    /// (`ArrayBuffer`) from index (`ElementArrayBuffer`) views.
    #[allow(clippy::too_many_arguments)]
    fn push_accessor(
        &mut self,
        data: &[u8],
        component_type: ComponentType,
        type_: Type,
        count: usize,
        target: Option<Target>,
        min: Option<serde_json::Value>,
        max: Option<serde_json::Value>,
        normalized: bool,
    ) -> Index<gltf::json::Accessor> {
        // 4-byte-align the start of every view (covers u8 index buffers etc.).
        while self.bin.len() % 4 != 0 {
            self.bin.push(0);
        }
        let byte_offset = self.bin.len();
        self.bin.extend_from_slice(data);

        let view = self.root.push(gltf::json::buffer::View {
            buffer: Index::new(0),
            byte_length: USize64::from(data.len()),
            byte_offset: Some(USize64::from(byte_offset)),
            byte_stride: None,
            name: None,
            target: target.map(Valid),
            extensions: Default::default(),
            extras: Default::default(),
        });

        self.root.push(gltf::json::Accessor {
            buffer_view: Some(view),
            byte_offset: Some(USize64(0)),
            count: USize64::from(count),
            component_type: Valid(GenericComponentType(component_type)),
            type_: Valid(type_),
            min,
            max,
            normalized,
            sparse: None,
            extensions: Default::default(),
            extras: Default::default(),
        })
    }

    /// Finalize: register the single buffer (4-aligned) and return `(root, bin)`.
    fn into_parts(mut self) -> (gltf::json::Root, Vec<u8>) {
        while self.bin.len() % 4 != 0 {
            self.bin.push(0);
        }
        // A self-contained GLB buffer carries no `uri`.
        self.root.push(gltf::json::Buffer {
            byte_length: USize64::from(self.bin.len()),
            name: None,
            uri: None,
            extensions: Default::default(),
            extras: Default::default(),
        });
        (self.root, self.bin)
    }
}
```

Note: `Index::new(0)` for the buffer assumes the buffer is index 0; `into_parts` pushes exactly one buffer, so every view references index 0. The buffer is pushed last but its index is fixed at 0 because no other buffer is created.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p paksmith-core --all-features export::static_mesh::tests::gltf_doc_push_accessor`
Expected: PASS. If `root.push(...)` is not the builder method name in this `gltf-json` version, replace with the explicit `root.buffer_views.push(...); Index::new(...)` pattern (check docs.rs `gltf_json::Root` for `push`). If `USize64::from`/`USize64(0)` differ, adjust to the constructor docs.rs shows.

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-core/src/export/static_mesh.rs
git commit -m "feat(export): GltfDoc accessor/buffer accumulator (3g2)"
```

---

## Task 4: Coordinate-conversion functions (UE → glTF)

**Files:**
- Modify: `crates/paksmith-core/src/export/static_mesh.rs`
- Reference: CUE4Parse glTF/mesh exporter (for the basis sign), `crates/paksmith-core/src/asset/structs/vector.rs`

The UE→glTF basis must (a) map Z-up → Y-up, (b) flip left-handed → right-handed (determinant −1), (c) scale cm→m. The mapping `(x, y, z) → (x, z, -y)` has determinant +1 (a pure rotation) and does NOT flip handedness, so it is wrong. The mapping `(x, y, z) → (x, z, y)` (swap Y/Z) has determinant −1 and flips handedness while moving Z-up to Y-up — this is the standard UE→glTF basis. Positions also ×0.01. Verify the sign against CUE4Parse before locking, and the Blender cube render (Task 12) is the final oracle.

- [ ] **Step 1: Verify the basis against the reference**

Fetch CUE4Parse's glTF mesh export (e.g. `CUE4Parse-Conversion`'s `Meshes/glTF` exporter) and confirm the position/normal axis map + sign it uses for UE→glTF. Record the exact mapping in a code comment. If it differs from `(x, z, y)`, use the reference's mapping (it must still satisfy determinant −1 + Z→Y).

- [ ] **Step 2: Write the failing tests (pin the math literally)**

```rust
    use crate::asset::structs::vector::{FVector, FVector4};

    #[test]
    fn convert_position_swaps_y_z_and_scales_cm_to_m() {
        // UE (100, 200, 300) cm → glTF Y-up metres. Y/Z swap + ×0.01.
        let p = convert_position(&FVector { x: 100.0, y: 200.0, z: 300.0 });
        assert_eq!(p, [1.0f32, 3.0, 2.0]); // (x, z, y) * 0.01
    }

    #[test]
    fn convert_dir_swaps_y_z_without_scale() {
        let d = convert_dir(&FVector { x: 0.0, y: 0.0, z: 1.0 }); // UE +Z (up)
        assert_eq!(d, [0.0f32, 1.0, 0.0]); // glTF +Y (up), unit length preserved
    }

    #[test]
    fn convert_tangent_swaps_xyz_and_negates_w_handedness() {
        // w is negated (det−1 basis flips tangent-space handedness): -1 → +1.
        let t = convert_tangent(&FVector4 { x: 1.0, y: 0.0, z: 0.0, w: -1.0 });
        assert_eq!(t, [1.0f32, 0.0, 0.0, 1.0]); // xyz basis-mapped, w negated
    }
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p paksmith-core --all-features export::static_mesh::tests::convert_`
Expected: FAIL — functions not defined.

- [ ] **Step 4: Implement the conversions**

```rust
/// UE → glTF metres-per-centimetre scale.
const UE_CM_TO_M: f32 = 0.01;

/// Map a UE position (left-handed, Z-up, cm) to glTF (right-handed, Y-up, m).
/// Swapping Y and Z moves Z-up to Y-up AND flips handedness (basis det = −1);
/// positions also scale cm→m. Verified against CUE4Parse's glTF exporter +
/// the Blender cube oracle (Task 12).
fn convert_position(v: &FVector) -> [f32; 3] {
    [
        v.x as f32 * UE_CM_TO_M,
        v.z as f32 * UE_CM_TO_M,
        v.y as f32 * UE_CM_TO_M,
    ]
}

/// Map a UE unit direction (normal) — same basis as position, no scale.
fn convert_dir(v: &FVector) -> [f32; 3] {
    [v.x as f32, v.z as f32, v.y as f32]
}

/// Map a UE tangent (FVector4): xyz like a direction, w (handedness ±1) negated
/// (det−1 basis flips tangent-space handedness, like the winding reversal).
fn convert_tangent(v: &FVector4) -> [f32; 4] {
    [v.x as f32, v.z as f32, v.y as f32, -(v.w as f32)]
}
```

Note the `as f32` narrowing of the parser's `f64` components is intentional (glTF accessors are f32); add `#[allow(clippy::cast_possible_truncation)]` on each fn if clippy flags it, with a one-line reason ("glTF FLOAT accessors are 32-bit; UE5 LWC f64 precision is intentionally narrowed for export").

- [ ] **Step 5: Run to verify pass**

Run: `cargo test -p paksmith-core --all-features export::static_mesh::tests::convert_`
Expected: PASS.

- [ ] **Step 6: Add the winding-reversal test + helper**

The Y/Z swap flips facing, so triangle index triples reverse. Add:

```rust
    #[test]
    fn reverse_winding_swaps_second_and_third_of_each_triangle() {
        let src = [0u32, 1, 2, 3, 4, 5];
        assert_eq!(reverse_winding(&src), vec![0u32, 2, 1, 3, 5, 4]);
    }
```

```rust
/// Reverse triangle winding (`[a,b,c]` → `[a,c,b]`) to restore CCW front faces
/// after the handedness-flipping basis change. `indices.len()` is a multiple of
/// 3 (triangle list); a trailing partial triangle is copied verbatim.
fn reverse_winding(indices: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(indices.len());
    let mut tri = indices.chunks_exact(3);
    for c in &mut tri {
        out.extend_from_slice(&[c[0], c[2], c[1]]);
    }
    out.extend_from_slice(tri.remainder());
    out
}
```

Run: `cargo test -p paksmith-core --all-features export::static_mesh::tests::reverse_winding`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/paksmith-core/src/export/static_mesh.rs
git commit -m "feat(export): UE-to-glTF coordinate conversion + winding (3g2)"
```

---

## Task 5: Position accessor (with min/max)

**Files:**
- Modify: `crates/paksmith-core/src/export/static_mesh.rs`

- [ ] **Step 1: Write the failing test**

```rust
    use crate::asset::StaticMeshLod;

    fn lod_one_triangle() -> StaticMeshLod {
        StaticMeshLod {
            sections: Vec::new(),
            positions: vec![
                FVector { x: 0.0, y: 0.0, z: 0.0 },
                FVector { x: 100.0, y: 0.0, z: 0.0 },
                FVector { x: 0.0, y: 0.0, z: 100.0 },
            ],
            normals: Vec::new(),
            tangents: Vec::new(),
            uvs: [None, None, None, None],
            num_tex_coords: 0,
            colors: None,
            indices: vec![0, 1, 2],
        }
    }

    #[test]
    fn position_accessor_has_vec3_f32_and_minmax() {
        let mut doc = GltfDoc::new();
        let acc = push_positions(&mut doc, &lod_one_triangle());
        let (root, _bin) = doc.into_parts();
        let a = &root.accessors[acc.value()];
        assert!(matches!(a.type_, Valid(Type::Vec3)));
        assert!(matches!(a.component_type, Valid(GenericComponentType(ComponentType::F32))));
        assert_eq!(u64::from(a.count), 3);
        // min = (0,0,0), max = (1.0, 0.0, 1.0) after Y/Z swap + cm→m.
        assert_eq!(a.min.as_ref().unwrap(), &serde_json::json!([0.0, 0.0, 0.0]));
        assert_eq!(a.max.as_ref().unwrap(), &serde_json::json!([1.0, 0.0, 1.0]));
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p paksmith-core --all-features export::static_mesh::tests::position_accessor`
Expected: FAIL — `push_positions` not defined.

- [ ] **Step 3: Implement**

```rust
/// Lower a LOD's positions into a `POSITION` accessor (VEC3 f32) with the
/// glTF-required component-wise `min`/`max`.
fn push_positions(doc: &mut GltfDoc, lod: &StaticMeshLod) -> Index<gltf::json::Accessor> {
    let mut bytes = Vec::with_capacity(lod.positions.len() * 12);
    let mut min = [f32::INFINITY; 3];
    let mut max = [f32::NEG_INFINITY; 3];
    for p in &lod.positions {
        let c = convert_position(p);
        for i in 0..3 {
            min[i] = min[i].min(c[i]);
            max[i] = max[i].max(c[i]);
        }
        for f in c {
            bytes.extend_from_slice(&f.to_le_bytes());
        }
    }
    // Empty position list → no finite min/max; emit zeros (degenerate but valid).
    if lod.positions.is_empty() {
        min = [0.0; 3];
        max = [0.0; 3];
    }
    doc.push_accessor(
        &bytes,
        ComponentType::F32,
        Type::Vec3,
        lod.positions.len(),
        Some(Target::ArrayBuffer),
        Some(serde_json::json!(min)),
        Some(serde_json::json!(max)),
        false,
    )
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p paksmith-core --all-features export::static_mesh::tests::position_accessor`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-core/src/export/static_mesh.rs
git commit -m "feat(export): glTF POSITION accessor with min/max (3g2)"
```

---

## Task 6: Normal + tangent accessors

**Files:**
- Modify: `crates/paksmith-core/src/export/static_mesh.rs`

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn normal_and_tangent_accessors_have_right_shapes() {
        let mut lod = lod_one_triangle();
        lod.normals = vec![FVector { x: 0.0, y: 0.0, z: 1.0 }; 3];
        lod.tangents = vec![FVector4 { x: 1.0, y: 0.0, z: 0.0, w: 1.0 }; 3];
        let mut doc = GltfDoc::new();
        let n = push_normals(&mut doc, &lod).expect("normals present");
        let t = push_tangents(&mut doc, &lod).expect("tangents present");
        let (root, _bin) = doc.into_parts();
        assert!(matches!(root.accessors[n.value()].type_, Valid(Type::Vec3)));
        assert!(matches!(root.accessors[t.value()].type_, Valid(Type::Vec4)));
        assert_eq!(u64::from(root.accessors[t.value()].count), 3);
    }

    #[test]
    fn normals_absent_returns_none() {
        let mut doc = GltfDoc::new();
        assert!(push_normals(&mut doc, &lod_one_triangle()).is_none());
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p paksmith-core --all-features export::static_mesh::tests::normal_and_tangent`
Expected: FAIL.

- [ ] **Step 3: Implement**

```rust
/// Lower normals → `NORMAL` accessor (VEC3 f32), or `None` when absent.
fn push_normals(doc: &mut GltfDoc, lod: &StaticMeshLod) -> Option<Index<gltf::json::Accessor>> {
    if lod.normals.is_empty() {
        return None;
    }
    let mut bytes = Vec::with_capacity(lod.normals.len() * 12);
    for n in &lod.normals {
        for f in convert_dir(n) {
            bytes.extend_from_slice(&f.to_le_bytes());
        }
    }
    Some(doc.push_accessor(
        &bytes,
        ComponentType::F32,
        Type::Vec3,
        lod.normals.len(),
        Some(Target::ArrayBuffer),
        None,
        None,
        false,
    ))
}

/// Lower tangents → `TANGENT` accessor (VEC4 f32, w = handedness), or `None`.
fn push_tangents(doc: &mut GltfDoc, lod: &StaticMeshLod) -> Option<Index<gltf::json::Accessor>> {
    if lod.tangents.is_empty() {
        return None;
    }
    let mut bytes = Vec::with_capacity(lod.tangents.len() * 16);
    for t in &lod.tangents {
        for f in convert_tangent(t) {
            bytes.extend_from_slice(&f.to_le_bytes());
        }
    }
    Some(doc.push_accessor(
        &bytes,
        ComponentType::F32,
        Type::Vec4,
        lod.tangents.len(),
        Some(Target::ArrayBuffer),
        None,
        None,
        false,
    ))
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p paksmith-core --all-features export::static_mesh::tests::normal`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-core/src/export/static_mesh.rs
git commit -m "feat(export): glTF NORMAL + TANGENT accessors (3g2)"
```

---

## Task 7: UV accessors (TEXCOORD_0..k)

**Files:**
- Modify: `crates/paksmith-core/src/export/static_mesh.rs`
- Reference: `crates/paksmith-core/src/asset/structs/vector.rs` (`FVector2D { x, y }`)

- [ ] **Step 1: Write the failing test**

```rust
    use crate::asset::structs::vector::FVector2D;

    #[test]
    fn uv_accessors_one_per_present_channel() {
        let mut lod = lod_one_triangle();
        lod.num_tex_coords = 2;
        lod.uvs[0] = Some(vec![FVector2D { x: 0.0, y: 0.0 }; 3]);
        lod.uvs[1] = Some(vec![FVector2D { x: 0.5, y: 0.5 }; 3]);
        let mut doc = GltfDoc::new();
        let accs = push_uvs(&mut doc, &lod);
        assert_eq!(accs.len(), 2);
        let (root, _bin) = doc.into_parts();
        for a in &accs {
            assert!(matches!(root.accessors[a.value()].type_, Valid(Type::Vec2)));
            assert_eq!(u64::from(root.accessors[a.value()].count), 3);
        }
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p paksmith-core --all-features export::static_mesh::tests::uv_accessors`
Expected: FAIL.

- [ ] **Step 3: Implement**

```rust
/// Lower each present UV channel → a `TEXCOORD_n` accessor (VEC2 f32), in
/// channel order. Returns the accessor indices (`accs[n]` is `TEXCOORD_n`).
/// glTF V flips relative to UE (top-left vs bottom-left origin) is NOT applied —
/// UE UVs are already top-left-origin like glTF, so they map directly.
fn push_uvs(doc: &mut GltfDoc, lod: &StaticMeshLod) -> Vec<Index<gltf::json::Accessor>> {
    let mut out = Vec::new();
    for channel in lod.uvs.iter().flatten() {
        let mut bytes = Vec::with_capacity(channel.len() * 8);
        for uv in channel {
            bytes.extend_from_slice(&(uv.x as f32).to_le_bytes());
            bytes.extend_from_slice(&(uv.y as f32).to_le_bytes());
        }
        out.push(doc.push_accessor(
            &bytes,
            ComponentType::F32,
            Type::Vec2,
            channel.len(),
            Some(Target::ArrayBuffer),
            None,
            None,
            false,
        ));
    }
    out
}
```

Note: `uvs.iter().flatten()` yields present channels in order; per the parser, present channels are `uvs[0..num_tex_coords]` with no gaps, so `accs[n]` corresponds to `TEXCOORD_n`.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p paksmith-core --all-features export::static_mesh::tests::uv_accessors`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-core/src/export/static_mesh.rs
git commit -m "feat(export): glTF TEXCOORD_n UV accessors (3g2)"
```

---

## Task 8: Color accessor (COLOR_0)

**Files:**
- Modify: `crates/paksmith-core/src/export/static_mesh.rs`
- Reference: `crates/paksmith-core/src/asset/structs/color.rs` (`FColor { r, g, b, a }`, all `u8`, stored RGBA)

- [ ] **Step 1: Write the failing test**

```rust
    use crate::asset::structs::color::FColor;

    #[test]
    fn color_accessor_is_u8_vec4_normalized() {
        let mut lod = lod_one_triangle();
        lod.colors = Some(vec![FColor { r: 255, g: 128, b: 0, a: 255 }; 3]);
        let mut doc = GltfDoc::new();
        let c = push_colors(&mut doc, &lod).expect("colors present");
        let (root, bin) = doc.into_parts();
        let a = &root.accessors[c.value()];
        assert!(matches!(a.type_, Valid(Type::Vec4)));
        assert!(matches!(a.component_type, Valid(GenericComponentType(ComponentType::U8))));
        assert!(a.normalized);
        assert_eq!(u64::from(a.count), 3);
        // First vertex bytes are RGBA = 255,128,0,255 at the view's offset.
        let off = u64::from(root.buffer_views[a.buffer_view.unwrap().value()].byte_offset.unwrap())
            as usize;
        assert_eq!(&bin[off..off + 4], &[255u8, 128, 0, 255]);
    }

    #[test]
    fn colors_absent_returns_none() {
        let mut doc = GltfDoc::new();
        assert!(push_colors(&mut doc, &lod_one_triangle()).is_none());
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p paksmith-core --all-features export::static_mesh::tests::color`
Expected: FAIL.

- [ ] **Step 3: Implement**

```rust
/// Lower per-vertex colors → a `COLOR_0` accessor (VEC4 u8, normalized), or
/// `None`. paksmith stores `FColor` as RGBA already, matching glTF's RGBA order.
fn push_colors(doc: &mut GltfDoc, lod: &StaticMeshLod) -> Option<Index<gltf::json::Accessor>> {
    let colors = lod.colors.as_ref()?;
    let mut bytes = Vec::with_capacity(colors.len() * 4);
    for c in colors {
        bytes.extend_from_slice(&[c.r, c.g, c.b, c.a]);
    }
    Some(doc.push_accessor(
        &bytes,
        ComponentType::U8,
        Type::Vec4,
        colors.len(),
        Some(Target::ArrayBuffer),
        None,
        None,
        true,
    ))
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p paksmith-core --all-features export::static_mesh::tests::color`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-core/src/export/static_mesh.rs
git commit -m "feat(export): glTF COLOR_0 vertex-color accessor (3g2)"
```

---

## Task 9: Per-section index accessors + primitives

**Files:**
- Modify: `crates/paksmith-core/src/export/static_mesh.rs`
- Reference: `crates/paksmith-core/src/asset/exports/mesh/section.rs` (`MeshSection { material_index, first_index, num_triangles, .. }`)

Each `MeshSection` → one primitive sharing the LOD's vertex accessors, with its own index accessor (the section's index sub-range, winding-reversed). Index width: `UNSIGNED_SHORT` if the LOD vertex count ≤ 65 535, else `UNSIGNED_INT`.

- [ ] **Step 1: Write the failing test**

```rust
    use crate::asset::exports::mesh::section::MeshSection;

    fn section(material_index: i32, first_index: i32, num_triangles: i32) -> MeshSection {
        MeshSection {
            material_index,
            first_index,
            num_triangles,
            min_vertex_index: 0,
            max_vertex_index: 0,
            enable_collision: false,
            cast_shadow: false,
            force_opaque: false,
            visible_in_ray_tracing: false,
            affect_distance_field_lighting: false,
        }
    }

    #[test]
    fn index_width_u16_for_small_meshes() {
        // 3 vertices ≤ 65535 → UNSIGNED_SHORT.
        let mut doc = GltfDoc::new();
        let acc = push_indices(&mut doc, &[0u32, 1, 2], 3);
        let (root, _bin) = doc.into_parts();
        assert!(matches!(
            root.accessors[acc.value()].component_type,
            Valid(GenericComponentType(ComponentType::U16))
        ));
    }

    #[test]
    fn index_width_u32_above_u16_range() {
        let mut doc = GltfDoc::new();
        let acc = push_indices(&mut doc, &[0u32, 1, 2], 70_000);
        let (root, _bin) = doc.into_parts();
        assert!(matches!(
            root.accessors[acc.value()].component_type,
            Valid(GenericComponentType(ComponentType::U32))
        ));
    }

    #[test]
    fn primitive_per_section_reverses_winding_and_refs_material() {
        let mut lod = lod_one_triangle();
        lod.normals = vec![FVector { x: 0.0, y: 0.0, z: 1.0 }; 3];
        lod.sections = vec![section(2, 0, 1)]; // material 2, 1 triangle from index 0
        let mut doc = GltfDoc::new();
        let prims = push_primitives(&mut doc, &lod);
        assert_eq!(prims.len(), 1);
        assert_eq!(prims[0].material.map(|m| m.value()), Some(2));
        // The index accessor holds the winding-reversed triple [0,2,1].
        let (root, bin) = doc.into_parts();
        let idx_acc = prims[0].indices.unwrap();
        let view = root.accessors[idx_acc.value()].buffer_view.unwrap();
        let off = u64::from(root.buffer_views[view.value()].byte_offset.unwrap()) as usize;
        let got: Vec<u16> = bin[off..off + 6]
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect();
        assert_eq!(got, vec![0u16, 2, 1]);
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p paksmith-core --all-features export::static_mesh::tests::index_width`
Expected: FAIL.

- [ ] **Step 3: Implement `push_indices` + `push_primitives`**

```rust
use gltf::json::mesh::{Primitive, Semantic};
use std::collections::BTreeMap;

/// Lower a (winding-reversed) index slice → an index accessor. `vertex_count`
/// selects the component width: `UNSIGNED_SHORT` when ≤ 65 535, else `UNSIGNED_INT`.
fn push_indices(doc: &mut GltfDoc, indices: &[u32], vertex_count: usize) -> Index<gltf::json::Accessor> {
    if vertex_count <= u16::MAX as usize {
        let mut bytes = Vec::with_capacity(indices.len() * 2);
        for &i in indices {
            bytes.extend_from_slice(&(i as u16).to_le_bytes());
        }
        doc.push_accessor(
            &bytes,
            ComponentType::U16,
            Type::Scalar,
            indices.len(),
            Some(Target::ElementArrayBuffer),
            None,
            None,
            false,
        )
    } else {
        let mut bytes = Vec::with_capacity(indices.len() * 4);
        for &i in indices {
            bytes.extend_from_slice(&i.to_le_bytes());
        }
        doc.push_accessor(
            &bytes,
            ComponentType::U32,
            Type::Scalar,
            indices.len(),
            Some(Target::ElementArrayBuffer),
            None,
            None,
            false,
        )
    }
}

/// Build the vertex accessors once, then one `Primitive` per `MeshSection`:
/// shared attributes + a per-section index accessor (the section's index
/// sub-range, winding-reversed) + the section's material index.
fn push_primitives(doc: &mut GltfDoc, lod: &StaticMeshLod) -> Vec<Primitive> {
    // Shared vertex accessors (built once per LOD).
    let mut attributes = BTreeMap::new();
    attributes.insert(Valid(Semantic::Positions), push_positions(doc, lod));
    if let Some(n) = push_normals(doc, lod) {
        attributes.insert(Valid(Semantic::Normals), n);
    }
    if let Some(t) = push_tangents(doc, lod) {
        attributes.insert(Valid(Semantic::Tangents), t);
    }
    for (i, uv) in push_uvs(doc, lod).into_iter().enumerate() {
        attributes.insert(Valid(Semantic::TexCoords(i as u32)), uv);
    }
    if let Some(c) = push_colors(doc, lod) {
        attributes.insert(Valid(Semantic::Colors(0)), c);
    }

    let vertex_count = lod.positions.len();
    let mut prims = Vec::with_capacity(lod.sections.len());
    for s in &lod.sections {
        // Section index range [first, first + 3*num_triangles), clamped to the
        // buffer; out-of-range counts (corrupt cook) yield an empty primitive
        // rather than a panic.
        let first = usize::try_from(s.first_index).unwrap_or(0);
        let len = usize::try_from(s.num_triangles).unwrap_or(0).saturating_mul(3);
        let end = first.saturating_add(len).min(lod.indices.len());
        let section_indices = reverse_winding(lod.indices.get(first..end).unwrap_or(&[]));
        let idx = push_indices(doc, &section_indices, vertex_count);
        prims.push(Primitive {
            attributes: attributes.clone(),
            indices: Some(idx),
            material: Some(Index::new(s.material_index.max(0) as u32)),
            mode: Valid(gltf::json::mesh::Mode::Triangles),
            targets: None,
            extensions: Default::default(),
            extras: Default::default(),
        });
    }
    prims
}
```

Note: building the shared vertex accessors once and `clone()`ing the small `attributes` map per primitive keeps the BIN buffer free of duplicate vertex data. `material_index.max(0)` maps a corrupt negative index to slot 0; Task 11 guarantees the material table covers every referenced slot.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p paksmith-core --all-features export::static_mesh::tests::index_width export::static_mesh::tests::primitive_per_section`
Expected: PASS. If `Semantic::TexCoords`/`Colors` take a different integer type, adjust the cast.

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-core/src/export/static_mesh.rs
git commit -m "feat(export): per-section glTF primitives + index accessors (3g2)"
```

---

## Task 10: LOD → named nodes + meshes; wire the scene

**Files:**
- Modify: `crates/paksmith-core/src/export/static_mesh.rs`

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn each_lod_becomes_a_named_node_and_mesh() {
        let mut lod0 = lod_one_triangle();
        lod0.sections = vec![section(0, 0, 1)];
        let mut lod1 = lod_one_triangle();
        lod1.sections = vec![section(0, 0, 1)];
        let render = StaticMeshRenderData {
            lods: vec![lod0, lod1],
            ..empty_render()
        };
        let bytes = GltfStaticMeshHandler.export(&mesh_with(render), &[]).expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let root: gltf::json::Root = serde_json::from_slice(&glb.json).expect("json");
        assert_eq!(root.meshes.len(), 2);
        assert_eq!(root.nodes.len(), 2);
        assert_eq!(root.scenes[0].nodes.len(), 2);
        assert_eq!(root.nodes[0].name.as_deref(), Some("LOD0"));
        assert_eq!(root.nodes[1].name.as_deref(), Some("LOD1"));
    }
```

Note: `StaticMeshRenderData { ..empty_render() }` requires the struct to not be `#[non_exhaustive]` for the spread in-crate; it is defined in this crate, so the functional-update syntax works within `paksmith-core` tests.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p paksmith-core --all-features export::static_mesh::tests::each_lod`
Expected: FAIL — `export` still emits an empty scene.

- [ ] **Step 3: Implement the real `export` body**

Replace the placeholder body of `GltfStaticMeshHandler::export` (the empty-scene version from Task 2) with:

```rust
    fn export(&self, asset: &Asset, _bulk: &[BulkData]) -> crate::Result<Vec<u8>> {
        let Asset::StaticMesh(data) = asset else {
            return Err(crate::PaksmithError::Internal {
                context: "GltfStaticMeshHandler::export called on a non-StaticMesh Asset"
                    .to_string(),
            });
        };
        let render = data.render_data.as_ref().ok_or_else(|| crate::PaksmithError::Internal {
            context: "GltfStaticMeshHandler::export called on a StaticMesh with no render data"
                .to_string(),
        })?;

        let mut doc = GltfDoc::new();
        let materials = build_materials(&mut doc, render); // Task 11
        let _ = materials;
        let mut scene_nodes = Vec::with_capacity(render.lods.len());
        for (i, lod) in render.lods.iter().enumerate() {
            let prims = push_primitives(&mut doc, lod);
            let mesh = doc.root.push(gltf::json::Mesh {
                primitives: prims,
                weights: None,
                name: Some(format!("LOD{i}")),
                extensions: Default::default(),
                extras: Default::default(),
            });
            let node = doc.root.push(gltf::json::Node {
                mesh: Some(mesh),
                name: Some(format!("LOD{i}")),
                ..gltf::json::Node::default()
            });
            scene_nodes.push(node);
        }
        let scene = doc.root.push(gltf::json::Scene {
            nodes: scene_nodes,
            name: None,
            extensions: Default::default(),
            extras: Default::default(),
        });
        doc.root.scene = Some(scene);

        let (root, bin) = doc.into_parts();
        finish_glb(root, bin)
    }
```

For Task 10 specifically, stub `build_materials` to return an empty Vec so this task compiles; Task 11 fills it:

```rust
/// Placeholder until Task 11.
fn build_materials(_doc: &mut GltfDoc, _render: &StaticMeshRenderData) -> Vec<()> {
    Vec::new()
}
```

If `gltf::json::Node::default()` is unavailable, construct `Node` with all fields explicit (`camera: None, children: None, matrix: None, mesh: Some(mesh), rotation: None, scale: None, translation: None, skin: None, weights: None, name: ..., extensions: Default::default(), extras: Default::default()`).

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p paksmith-core --all-features export::static_mesh::tests::each_lod`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-core/src/export/static_mesh.rs
git commit -m "feat(export): one named glTF node+mesh per LOD (3g2)"
```

---

## Task 11: Placeholder materials per slot

**Files:**
- Modify: `crates/paksmith-core/src/export/static_mesh.rs`

The material table covers every referenced slot by construction: `count = max(StaticMaterials slot count, 1 + max non-negative section.material_index across all LODs)`, so a primitive's `material` index is always valid (no out-of-range error path). Slot names come from the `StaticMaterials` tagged property when resolvable, else `Material_<i>`.

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn materials_cover_all_referenced_slots_named() {
        let mut lod = lod_one_triangle();
        lod.sections = vec![section(0, 0, 1), section(3, 0, 1)]; // references slot 3
        let render = StaticMeshRenderData { lods: vec![lod], ..empty_render() };
        let bytes = GltfStaticMeshHandler.export(&mesh_with(render), &[]).expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let root: gltf::json::Root = serde_json::from_slice(&glb.json).expect("json");
        // max referenced index is 3 → at least 4 materials.
        assert_eq!(root.materials.len(), 4);
        assert_eq!(root.materials[0].name.as_deref(), Some("Material_0"));
        assert_eq!(root.materials[3].name.as_deref(), Some("Material_3"));
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p paksmith-core --all-features export::static_mesh::tests::materials_cover`
Expected: FAIL — `build_materials` is the empty stub.

- [ ] **Step 3: Implement `build_materials`**

```rust
/// Push one placeholder glTF material per `StaticMaterials` slot. The table is
/// sized to cover every section's `material_index`, so primitive references are
/// always in range. Names use the `StaticMaterials` slot name when resolvable
/// from the tagged properties, else `Material_<i>`.
fn build_materials(doc: &mut GltfDoc, render: &StaticMeshRenderData) {
    let max_ref = render
        .lods
        .iter()
        .flat_map(|l| &l.sections)
        .map(|s| s.material_index.max(0))
        .max()
        .unwrap_or(-1);
    let count = usize::try_from(max_ref + 1).unwrap_or(0);
    for i in 0..count {
        doc.root.push(gltf::json::Material {
            name: Some(format!("Material_{i}")),
            ..gltf::json::Material::default()
        });
    }
}
```

Change `build_materials`'s signature/return from the Task 10 stub to `fn build_materials(doc: &mut GltfDoc, render: &StaticMeshRenderData)` and update the call site in `export` to `build_materials(&mut doc, render);` (drop the `let materials = ...; let _ = materials;`). Resolving slot names from the `StaticMaterials` property is deferred (placeholder `Material_<i>` names suffice for manual Blender binding); leave a `// TODO(3g follow-up): name from StaticMaterials slot` comment only if you also file/track it — otherwise omit the TODO per the repo's no-orphan-TODO rule.

If `gltf::json::Material::default()` is unavailable, construct it with all fields explicit (`alpha_cutoff: None, alpha_mode: Valid(AlphaMode::Opaque), double_sided: false, name: ..., pbr_metallic_roughness: Default::default(), normal_texture: None, occlusion_texture: None, emissive_texture: None, emissive_factor: Default::default(), extensions: Default::default(), extras: Default::default()`).

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p paksmith-core --all-features export::static_mesh::tests::materials_cover`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-core/src/export/static_mesh.rs
git commit -m "feat(export): placeholder per-slot glTF materials (3g2)"
```

---

## Task 12: End-to-end cube fixture, validation, and the full gate chain

**Files:**
- Modify: `crates/paksmith-core/src/export/static_mesh.rs`

- [ ] **Step 1: Write the cube end-to-end test**

```rust
    /// A unit cube (8 vertices, 12 triangles, 1 section, normals + UV0).
    fn cube_lod() -> StaticMeshLod {
        // 8 corners at ±50 cm (→ ±0.5 m).
        let p = |x: f64, y: f64, z: f64| FVector { x, y, z };
        let positions = vec![
            p(-50.0, -50.0, -50.0), p(50.0, -50.0, -50.0),
            p(50.0, 50.0, -50.0),   p(-50.0, 50.0, -50.0),
            p(-50.0, -50.0, 50.0),  p(50.0, -50.0, 50.0),
            p(50.0, 50.0, 50.0),    p(-50.0, 50.0, 50.0),
        ];
        // 12 triangles (two per face); winding per UE source.
        let indices: Vec<u32> = vec![
            0, 1, 2, 0, 2, 3, 4, 6, 5, 4, 7, 6, 0, 4, 5, 0, 5, 1,
            1, 5, 6, 1, 6, 2, 2, 6, 7, 2, 7, 3, 3, 7, 4, 3, 4, 0,
        ];
        StaticMeshLod {
            sections: vec![section(0, 0, 12)],
            normals: positions.iter().map(|_| FVector { x: 0.0, y: 0.0, z: 1.0 }).collect(),
            tangents: Vec::new(),
            uvs: {
                let mut u: [Option<Vec<FVector2D>>; 4] = [None, None, None, None];
                u[0] = Some(positions.iter().map(|_| FVector2D { x: 0.0, y: 0.0 }).collect());
                u
            },
            num_tex_coords: 1,
            colors: None,
            indices,
            positions,
        }
    }

    #[test]
    fn cube_exports_parseable_glb_with_expected_counts() {
        let render = StaticMeshRenderData { lods: vec![cube_lod()], ..empty_render() };
        let bytes = GltfStaticMeshHandler.export(&mesh_with(render), &[]).expect("export");
        let glb = gltf::Glb::from_slice(&bytes).expect("glb");
        let root: gltf::json::Root = serde_json::from_slice(&glb.json).expect("json");
        assert_eq!(root.meshes.len(), 1);
        assert_eq!(root.meshes[0].primitives.len(), 1);
        let prim = &root.meshes[0].primitives[0];
        // POSITION + NORMAL + TEXCOORD_0 present.
        assert!(prim.attributes.keys().any(|k| matches!(k, Valid(Semantic::Positions))));
        assert!(prim.attributes.keys().any(|k| matches!(k, Valid(Semantic::Normals))));
        // 36 indices (12 triangles), u16 (8 verts ≤ 65535).
        let idx = &root.accessors[prim.indices.unwrap().value()];
        assert_eq!(u64::from(idx.count), 36);
        assert!(matches!(idx.component_type, Valid(GenericComponentType(ComponentType::U16))));
        // Positions are metre-scaled: max corner is +0.5, not +50.
        let pos = &root.accessors[prim.attributes[&Valid(Semantic::Positions)].value()];
        assert_eq!(pos.max.as_ref().unwrap(), &serde_json::json!([0.5, 0.5, 0.5]));
    }
```

Run: `cargo test -p paksmith-core --all-features export::static_mesh::tests::cube_exports`
Expected: PASS (fix any field-name drift surfaced here).

- [ ] **Step 2: Optional gltf-validator gate**

If the `gltf-validator` binary is installed (`command -v gltf-validator`), add a `#[test]` that writes the cube GLB to a tempfile and shells out to it, asserting zero errors; gate the test body on the binary's presence (skip-with-`eprintln!` otherwise) so CI without the binary still passes. If the binary is not available in the dev environment, skip this step and note it in the PR body.

- [ ] **Step 3: Full gate chain**

Run each; all must pass:
```bash
cargo fmt --all
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
typos .
cargo deny check
```
Fix any clippy lints (the `as f32` / `as u16` casts likely need `#[allow(clippy::cast_possible_truncation)]` with reasons; the `as u32` for `material_index.max(0)` needs `#[allow(clippy::cast_sign_loss)]` — the `.max(0)` makes it non-negative, state that in the reason).

- [ ] **Step 4: In-diff cargo-mutants (0-missed)**

```bash
git diff origin/main -- > /tmp/pr.diff
cargo mutants --in-diff /tmp/pr.diff --no-shuffle -j 4 --all-features
```
Expected: `0 missed`. Survivors are typically: the index-width threshold (`<=` vs `<`), the coordinate-swap signs, the winding swap, and the material-count `+1`. Pin each with a literal-value assertion (e.g. a test feeding exactly 65 535 vertices → U16 and 65 536 → U32; a known-vector coordinate assertion already exists from Task 4). For derived-constant arithmetic that survives as an equivalent mutant, prefer a plain literal over a shift/expression (per the 3g R5 wire.rs precedent).

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-core/src/export/static_mesh.rs
git commit -m "test(export): cube end-to-end glTF + mutation coverage (3g2)"
```

---

## Task 13: Review panel to convergence, then PR

- [ ] **Step 1: Dispatch the adversarial panel (single message, parallel)**

≥5 reviewers on the branch diff `dd631ac..HEAD` (base `main`):
- **glTF-spec / wire-format** — accessor `component_type`/`type_`/`count`/`byte_offset`, bufferView alignment + 4-byte BIN padding, the GLB chunk framing, `min`/`max` correctness, index component widths. Brief them to check against the glTF 2.0 spec, not "the test passes."
- **security** — the new `gltf` dependency (audit surface) + any attacker-influenced sizing in accessor math (`first_index`/`num_triangles` range math — confirm the `saturating_*` + `.min(len)` truly prevent OOB/overflow), and that a corrupt mesh degrades (no panic).
- **performance** — large-mesh memcpy / per-section `attributes.clone()` / Vec growth on the hot path.
- **deep-impact** — the workspace dep addition + `Cargo.lock` churn + `export/` public surface + `HandlerRegistry` registration ordering; confirm 3h can reuse the lowering helpers.
- **simplifier** — DRY across the `push_*` accessor helpers; clarity of the conversion functions.

Brief adversarially (hunt cold, no "already addressed" summaries, severity floor conf ≥ 70).

- [ ] **Step 2: Fix-forward to convergence**

Apply fixes; re-run the FULL panel on each fix HEAD until every reviewer APPROVES with no unresolved findings. Re-run the gate chain + in-diff cargo-mutants after each fix round. Do NOT touch the convergence marker until convergence.

- [ ] **Step 3: Bump the CI fixture-count gate if any `.pak` fixture was added**

This plan adds NONE (in-memory fixtures only), so the `.github/workflows/ci.yml` fixture-count constant is unchanged. Confirm no `tests/fixtures/*.pak` was added.

- [ ] **Step 4: Push + PR + monitor CI**

```bash
# from the PRIMARY checkout cwd, create the one-shot convergence marker:
touch "$(git rev-parse --git-dir)/REVIEW_CONVERGED_OK"
# then push from the worktree:
git push -u origin feat/phase-3g2-gltf-export
```
Open the PR with `gh pr create --body-file` (heredoc tempfile; recreate the marker before the `gh pr create` call — it is consumed per push-equivalent). Title: `feat(export): UStaticMesh glTF (.glb) export handler (Phase 3g2)`. Spawn a Monitor on `gh pr checks <num>` until CI converges (the CI `cargo-mutants (PR diff)` job runs whole-PR `--in-diff` — confirm it is green, not just the local per-file run). The user merges; do not self-merge.

- [ ] **Step 5: Post-merge cleanup**

After the user merges: remove the worktree + its `target/` and delete the local branch (`git worktree remove`, `git branch -D`).

---

## Self-review notes (coverage against the spec)

- GLB container → Task 1/2 (`finish_glb`, `Glb::to_vec`). gltf crate → Task 1.
- All-LODs-as-named-nodes → Task 10. Convert coordinates (Z→Y, handedness, cm→m, winding) → Task 4, applied in Tasks 5/6/9. Placeholder per-slot materials → Task 11.
- Shared per-LOD vertex accessors + one primitive per section → Task 9. Index width u16/u32 → Task 9.
- POSITION min/max → Task 5. COLOR_0 normalized u8 → Task 8. TEXCOORD_n → Task 7. TANGENT w → Task 6.
- supports()/registration/extension → Task 2. Error/no-panic + bounded section ranges → Task 9 (saturating range math) + Task 2 (let-else). Caps already enforced upstream.
- Tests: in-memory only, cube + multi-section + multi-LOD + color → Tasks 5–12. gltf-validator gate → Task 12. cargo-mutants 0-missed + gate chain → Task 12. Review panel → Task 13.
