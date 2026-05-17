# Changelog

## [0.1.1](https://github.com/r6e/paksmith/compare/v0.1.0...v0.1.1) (2026-05-17)


### Features

* **asset:** add NameTable — FName pool with dual CityHash16 trailer (Phase 2a Task 6) ([#162](https://github.com/r6e/paksmith/issues/162)) ([a70d976](https://github.com/r6e/paksmith/commit/a70d976611ca5c26b6aab55aa22149d1d783530b))
* **asset:** add ObjectExport + ExportTable for UE 4.21–UE 5.x (Phase 2a Task 8) ([#176](https://github.com/r6e/paksmith/issues/176)) ([26c9062](https://github.com/r6e/paksmith/commit/26c90624ed90706c80399b120996ad4df3aa62c4))
* **asset:** add ObjectImport + ImportTable for UE 4.21–UE 5.x (Phase 2a Task 7) ([#170](https://github.com/r6e/paksmith/issues/170)) ([f175952](https://github.com/r6e/paksmith/commit/f17595283feafe48b542f581e853b1044d32ad60))
* **asset:** add Package::read_from orchestrator + AssetContext ([#182](https://github.com/r6e/paksmith/issues/182)) ([a1f53cf](https://github.com/r6e/paksmith/commit/a1f53cff81493fb74f8e6b1525b49ba11a729eb0))
* **asset:** add PackageSummary — FPackageFileSummary orchestrator + cooked-only enforcement (Phase 2a Task 9) ([#177](https://github.com/r6e/paksmith/issues/177)) ([442071c](https://github.com/r6e/paksmith/commit/442071c4ea6cec189c2bb465b3088e6d1aa398e7))
* **asset:** add PropertyBag::Opaque + MAX_PROPERTY_DEPTH (Phase 2a Task 10) ([#178](https://github.com/r6e/paksmith/issues/178)) ([ba40798](https://github.com/r6e/paksmith/commit/ba40798ca0622f0321982f886c1ab666ced10c7a))
* **asset:** close Phase 2a audit gaps — Asset enum + FName resolution + docs ([#202](https://github.com/r6e/paksmith/issues/202)) ([fb5b68b](https://github.com/r6e/paksmith/commit/fb5b68b64355c03f76b78bc2843e44bbc7e3af1e))
* **core:** add PakReader::from_reader + from_bytes entry points ([#254](https://github.com/r6e/paksmith/issues/254)) ([feea191](https://github.com/r6e/paksmith/commit/feea1913a9d9a0003fafa3f6ba951de3bebd89b8))
* **fixture-gen:** synthetic UE 4.27 uasset + unreal_asset cross-validation ([#185](https://github.com/r6e/paksmith/issues/185)) ([0ffd20e](https://github.com/r6e/paksmith/commit/0ffd20e411477539c77aafddb5fd10a5ef3446ca))
* **testing:** add minimal UE 4.27 uasset builder under __test_utils (Phase 2a Task 10b) ([#179](https://github.com/r6e/paksmith/issues/179)) ([9ed788b](https://github.com/r6e/paksmith/commit/9ed788bbedd394d35b452a2666c61bf289f43120))


### Bug Fixes

* **asset:** close Phase 2a second-pass audit findings ([#207](https://github.com/r6e/paksmith/issues/207)) ([ffabad4](https://github.com/r6e/paksmith/commit/ffabad495504fb37d3e55083a0b0405bb2fcb8ee))
* **asset:** mask licensee-version high bit in EngineVersion display ([#234](https://github.com/r6e/paksmith/issues/234)) ([a34a850](https://github.com/r6e/paksmith/commit/a34a850b3b29f97f7d61f9426aa593de5492602f))
* **asset:** version-gate searchable_names_offset + preload_dependency_* in PackageSummary ([#230](https://github.com/r6e/paksmith/issues/230)) ([9ee2b34](https://github.com/r6e/paksmith/commit/9ee2b34d4933d507359c16766badad83f94e483d))
* **asset:** wire-format correctness corrections vs CUE4Parse ([#224](https://github.com/r6e/paksmith/issues/224)) ([804bcb5](https://github.com/r6e/paksmith/commit/804bcb5e00d5913d4e036be196cd249d96514eff))
* **core:** add MAX_FLAT_INDEX_ENTRIES hard cap (v3-v9 [#128](https://github.com/r6e/paksmith/issues/128) follow-up) ([#226](https://github.com/r6e/paksmith/issues/226)) ([70a4de5](https://github.com/r6e/paksmith/commit/70a4de5243d0e26a9d810004b1bd790d7113155f))
* **core:** add PHI/FDI cross-validation at open time ([#201](https://github.com/r6e/paksmith/issues/201)) ([39e4876](https://github.com/r6e/paksmith/commit/39e4876c1b93adc8a860444bddaade3fe742f534))
* **core:** cap encoded compressed_size symmetrically for multi-block ([#225](https://github.com/r6e/paksmith/issues/225)) ([9e8f342](https://github.com/r6e/paksmith/commit/9e8f342865c240d65267649ce1dacc2985f1bfb6))
* **core:** cap single-block encoded compressed_size ([#187](https://github.com/r6e/paksmith/issues/187)) ([c3d7993](https://github.com/r6e/paksmith/commit/c3d799345e0eafba37e107914c5f7e9ea5236134))
* **core:** cap v10+ main-index allocation with MAX_INDEX_SIZE ([#180](https://github.com/r6e/paksmith/issues/180)) ([0cd7891](https://github.com/r6e/paksmith/commit/0cd7891ea6549f98460474a24bff0aed595b7822))
* **core:** footer + FName + allocation discipline hardening ([#190](https://github.com/r6e/paksmith/issues/190)) ([7e77c51](https://github.com/r6e/paksmith/commit/7e77c5170c41106ddd668d19bd7fd7d3e21df46d))
* **core:** pre-validate v10+ FDI/PHI region bounds against file_size ([#183](https://github.com/r6e/paksmith/issues/183)) ([4977aa5](https://github.com/r6e/paksmith/commit/4977aa5f291de28e334099bbffbbb78c699636bf))
* **core:** reject out-of-order compression blocks ([#184](https://github.com/r6e/paksmith/issues/184)) ([e019394](https://github.com/r6e/paksmith/commit/e0193943455436731ae28317ed1dc6cd75f24bed))
* **security:** parser hardening — embedded NULs + symlink awareness ([#239](https://github.com/r6e/paksmith/issues/239)) ([08c4a33](https://github.com/r6e/paksmith/commit/08c4a33ae138f58a4aa4107c9716db43beff16a8))
