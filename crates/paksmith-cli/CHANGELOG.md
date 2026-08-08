# Changelog

## [0.2.0](https://github.com/r6e/paksmith/compare/v0.1.0...v0.2.0) (2026-08-08)


### ⚠ BREAKING CHANGES

* **profile:** honour --format across profile subcommands and dedupe repeated registry ids ([#725](https://github.com/r6e/paksmith/issues/725))
* **profile:** `DetectRules` gains a public field and `#[non_exhaustive]`. Both are source-breaking for downstream struct literals; the attribute lands in the same window as the break already being taken, per the timing rule `asset::mappings` documents, so the next field addition is free. In-repo construction is unaffected.
* **cli:** `paksmith list`/`paksmith search` --format json now emit { "schema_version": 1, "entries": [...] } instead of a bare top-level array. Consumers using `jq '.[]'` (or equivalent) must switch to `jq '.entries[]'`.
* **export:** add FormatHandler trait + class-name dispatch ([#467](https://github.com/r6e/paksmith/issues/467))

### Features

* **asset:** add Usmap::from_path constructor ([#409](https://github.com/r6e/paksmith/issues/409)) ([e03f954](https://github.com/r6e/paksmith/commit/e03f9540f7d6a7490e1de0401344261a68ed5615))
* **asset:** close Phase 2a audit gaps — Asset enum + FName resolution + docs ([#202](https://github.com/r6e/paksmith/issues/202)) ([fb5b68b](https://github.com/r6e/paksmith/commit/fb5b68b64355c03f76b78bc2843e44bbc7e3af1e))
* **asset:** wire property iterator into Package + reshape per-export Serialize ([#283](https://github.com/r6e/paksmith/issues/283)) ([f80175a](https://github.com/r6e/paksmith/commit/f80175afe54cb974f7d3f577d5f3973a11071ee3))
* **cli:** add --mappings flag for unversioned asset inspection ([#334](https://github.com/r6e/paksmith/issues/334)) ([ea5c8e8](https://github.com/r6e/paksmith/commit/ea5c8e857ce1e5cec13695439e980fc39c80bc84))
* **cli:** add --quiet, table color, list/search schema_version envelope, and search --filter ([#709](https://github.com/r6e/paksmith/issues/709)) ([c2519f7](https://github.com/r6e/paksmith/commit/c2519f7f65fa2df35b965f67aec3a5f9b0581630))
* **cli:** add extract subcommand (Phase 4a) ([#586](https://github.com/r6e/paksmith/issues/586)) ([d45904b](https://github.com/r6e/paksmith/commit/d45904b994f12fe9adb88facd4fc40cf902f3308))
* **cli:** add inspect selection, schema_version, and table view (Phase 4b) ([#587](https://github.com/r6e/paksmith/issues/587)) ([afecd97](https://github.com/r6e/paksmith/commit/afecd9718921d07872c0417daf1d57bf4fcf7b83))
* **cli:** add inspect subcommand emitting Package JSON ([#193](https://github.com/r6e/paksmith/issues/193)) ([b2f3c9c](https://github.com/r6e/paksmith/commit/b2f3c9cd79c84b8ead1ac8903fe790e80b8e4a77))
* **cli:** add mappings pipeline — extract --mappings, profile MappingsSource, --game supplies mappings ([#707](https://github.com/r6e/paksmith/issues/707)) ([4de06ed](https://github.com/r6e/paksmith/commit/4de06ed9df29df25b7ac58eb318426bb4ae0095f))
* **cli:** add search command (Phase 4c, completes Phase 4) ([#588](https://github.com/r6e/paksmith/issues/588)) ([97c7600](https://github.com/r6e/paksmith/commit/97c76008dc2c2f0870080cd5cb12597e7ee91af0))
* **core:** add container-agnostic open/read seam ahead of iostore ([#711](https://github.com/r6e/paksmith/issues/711)) ([d59c78d](https://github.com/r6e/paksmith/commit/d59c78dcdd9e9b4302f4aca356e33a738c91fab5))
* **core:** add game profiles and aes key management (phase 5b) ([#590](https://github.com/r6e/paksmith/issues/590)) ([434ec7b](https://github.com/r6e/paksmith/commit/434ec7b0e2f6a100b60767a9ef26483e3013c469))
* **core:** add signed remote profile registry with offline cache (phase 5c) ([#591](https://github.com/r6e/paksmith/issues/591)) ([d1430c6](https://github.com/r6e/paksmith/commit/d1430c6d7ffbe3056661cec98ff6ed1599ad818d))
* **core:** decrypt aes-256 encrypted paks via --aes-key (phase 5a) ([#589](https://github.com/r6e/paksmith/issues/589)) ([416c81c](https://github.com/r6e/paksmith/commit/416c81c8cfc6be7ed0cef434ce7b8039415e6d43))
* **export:** add FormatHandler trait + class-name dispatch ([#467](https://github.com/r6e/paksmith/issues/467)) ([996d780](https://github.com/r6e/paksmith/commit/996d780e4ecfe4c6298b73c458fd4ab6a81d14dc))
* **export:** add localization table (.locres) handler ([#701](https://github.com/r6e/paksmith/issues/701)) ([a53d469](https://github.com/r6e/paksmith/commit/a53d4694b2b6c49beadfc6bcc22f14b0624c766c))
* **gui:** add debug console with tracing ring buffer and filters (phase 7c) ([#621](https://github.com/r6e/paksmith/issues/621)) ([135beb5](https://github.com/r6e/paksmith/commit/135beb5f53a073ad1f3ecf605b621a2be3a7d0f2))
* **gui:** phase 6 GUI shell (Iced two-pane explorer + core resolve refactor) ([#593](https://github.com/r6e/paksmith/issues/593)) ([7ae4c94](https://github.com/r6e/paksmith/commit/7ae4c944f7283aa9191e0593a622a6be5ccb57d1))
* **mesh:** resolve external-bulk skeletal LOD geometry ([#705](https://github.com/r6e/paksmith/issues/705)) ([5208d82](https://github.com/r6e/paksmith/commit/5208d82045981d2f6358e92d8fd6d54552b66d2c))
* **profile:** add game auto-detection (profile detect + --detect) ([#592](https://github.com/r6e/paksmith/issues/592)) ([2e50288](https://github.com/r6e/paksmith/commit/2e502885c5c93ffcf60c28ba9f2e3a492569c7d8))
* **profile:** add pak_paths so profiles locate a game's archives ([#712](https://github.com/r6e/paksmith/issues/712)) ([da47131](https://github.com/r6e/paksmith/commit/da47131183d04ac5598313c413d2fb3f5e80f329))
* **profile:** consume engine_version in version-ambiguous parse gates ([#714](https://github.com/r6e/paksmith/issues/714)) ([319e3e6](https://github.com/r6e/paksmith/commit/319e3e6b2c87ea268d317b9bdb60dea1b77b2508))
* **profile:** detect games by byte signature in binaries ([#724](https://github.com/r6e/paksmith/issues/724)) ([8f322d2](https://github.com/r6e/paksmith/commit/8f322d25a3546080c41820871c4b09fbf9b998c0))
* **profile:** honour --format across profile subcommands and dedupe repeated registry ids ([#725](https://github.com/r6e/paksmith/issues/725)) ([f19248f](https://github.com/r6e/paksmith/commit/f19248fd560e2d6c6d685a906dfe0460990f51d7))
* **profile:** resolve show and test against cached registry profiles ([#715](https://github.com/r6e/paksmith/issues/715)) ([0cb4944](https://github.com/r6e/paksmith/commit/0cb4944da0c74ae70d224a2bbaf15b2fe802c1bd))
* **texture:** export TextureCube, Texture2DArray, and VolumeTexture as strip PNGs ([#703](https://github.com/r6e/paksmith/issues/703)) ([6292a83](https://github.com/r6e/paksmith/commit/6292a83d99284a6a5ec0f116bf2033f5f34cad2d))


### Bug Fixes

* **asset:** wire-format correctness corrections vs CUE4Parse ([#224](https://github.com/r6e/paksmith/issues/224)) ([804bcb5](https://github.com/r6e/paksmith/commit/804bcb5e00d5913d4e036be196cd249d96514eff))
* **release:** revert phantom 0.2.0 version bump back to 0.1.0 ([#475](https://github.com/r6e/paksmith/issues/475)) ([054d418](https://github.com/r6e/paksmith/commit/054d41899b2af15af44a007ece3a837c08a7841a))


### Performance Improvements

* **cli:** buffer paksmith inspect stdout to collapse per-value syscalls ([#427](https://github.com/r6e/paksmith/issues/427)) ([51deaca](https://github.com/r6e/paksmith/commit/51deacaf0074ca4cd24ab52237f9ba7a0c538df7))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * paksmith-core bumped from 0.1 to 0.2.0
