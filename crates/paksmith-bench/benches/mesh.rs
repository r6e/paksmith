//! Phase 3g static-mesh → glTF lowering benchmark.
//!
//! Drives `GltfStaticMeshHandler::export` on a 300K-vertex / 100K-triangle mesh
//! with the full attribute set (positions + normals + tangents + UV0 + colors).
//! Exercises the per-vertex conversion + accessor packing + index emission hot
//! path (the surface the A1 redundant-conversion-pass and A2 index-copy findings
//! target). Throughput reported in vertices/s.

#![allow(unused_results, missing_docs)]

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use paksmith_core::export::{FormatHandler, GltfStaticMeshHandler};
use paksmith_core::testing::bench::large_static_mesh;

const VERTS: u32 = 300_000;

fn mesh_gltf_lower(c: &mut Criterion) {
    let asset = large_static_mesh(VERTS);
    let mut group = c.benchmark_group("mesh_gltf_lower_300k_verts");
    group.throughput(Throughput::Elements(u64::from(VERTS)));
    group.bench_function("export", |b| {
        b.iter(|| {
            let glb = GltfStaticMeshHandler
                .export(black_box(&asset), &[])
                .expect("static mesh export");
            black_box(glb);
        });
    });
    group.finish();
}

criterion_group!(benches, mesh_gltf_lower);
criterion_main!(benches);
