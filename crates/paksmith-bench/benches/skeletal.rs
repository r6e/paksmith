//! Phase 3h skeletal-mesh → glTF lowering benchmark.
//!
//! Drives `GltfSkeletalMeshHandler::export` on a 100K-vertex, 4-influence mesh
//! skinned to a 100-bone skeleton. Exercises the per-vertex skin-attribute build
//! (owning-section lookup + bone-map remap + weight renormalization +
//! JOINTS_0/WEIGHTS_0 packing) on top of the shared geometry lowering.
//! Throughput reported in vertices/s.

#![allow(unused_results, missing_docs)]

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use paksmith_core::export::{FormatHandler, GltfSkeletalMeshHandler};
use paksmith_core::testing::bench::large_skeletal_mesh;

const VERTS: u32 = 100_000;
const BONES: u16 = 100;

fn skeletal_gltf_lower(c: &mut Criterion) {
    let asset = large_skeletal_mesh(VERTS, BONES);
    let mut group = c.benchmark_group("skeletal_gltf_lower_100k_verts");
    group.throughput(Throughput::Elements(u64::from(VERTS)));
    group.bench_function("export", |b| {
        b.iter(|| {
            let glb = GltfSkeletalMeshHandler
                .export(black_box(&asset), &[])
                .expect("skeletal mesh export");
            black_box(glb);
        });
    });
    group.finish();
}

criterion_group!(benches, skeletal_gltf_lower);
criterion_main!(benches);
