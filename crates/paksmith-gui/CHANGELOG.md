# Changelog

## [0.2.0](https://github.com/r6e/paksmith/compare/v0.1.0...v0.2.0) (2026-10-10)


### ⚠ BREAKING CHANGES

* **core:** `PropertyValue::Object { name }` is an `Arc<str>`, not a `String`. Build one with `.into()` from `&str` or `String`, compare through `&*name`, and use `to_string()` where an owned `String` is needed. Serialized output is unchanged.
* **export:** add FormatHandler trait + class-name dispatch ([#467](https://github.com/r6e/paksmith/issues/467))

### Features

* **cli:** add mappings pipeline — extract --mappings, profile MappingsSource, --game supplies mappings ([#707](https://github.com/r6e/paksmith/issues/707)) ([4de06ed](https://github.com/r6e/paksmith/commit/4de06ed9df29df25b7ac58eb318426bb4ae0095f))
* **core:** add container-agnostic open/read seam ahead of iostore ([#711](https://github.com/r6e/paksmith/issues/711)) ([d59c78d](https://github.com/r6e/paksmith/commit/d59c78dcdd9e9b4302f4aca356e33a738c91fab5))
* **core:** expose entry offset, compression method and SHA-1 through EntryMetadata ([#752](https://github.com/r6e/paksmith/issues/752)) ([18c95e9](https://github.com/r6e/paksmith/commit/18c95e91a9a495dfa84cbda94adc5682cdd77fcd))
* **export:** add FormatHandler trait + class-name dispatch ([#467](https://github.com/r6e/paksmith/issues/467)) ([996d780](https://github.com/r6e/paksmith/commit/996d780e4ecfe4c6298b73c458fd4ab6a81d14dc))
* **gui:** add audio player view mode (phase 7d) ([#633](https://github.com/r6e/paksmith/issues/633)) ([b45d55c](https://github.com/r6e/paksmith/commit/b45d55cb8fca1b4e6f0ac0f0546d5528016917a8))
* **gui:** add debug console with tracing ring buffer and filters (phase 7c) ([#621](https://github.com/r6e/paksmith/issues/621)) ([135beb5](https://github.com/r6e/paksmith/commit/135beb5f53a073ad1f3ecf605b621a2be3a7d0f2))
* **gui:** add Export As… export with core export façade (phase 7c) ([#620](https://github.com/r6e/paksmith/issues/620)) ([4348e7b](https://github.com/r6e/paksmith/commit/4348e7ba9c00faba47ab2945b8da8eb84b19a042))
* **gui:** add file-tree context menu (phase 7c) ([#619](https://github.com/r6e/paksmith/issues/619)) ([8437d41](https://github.com/r6e/paksmith/commit/8437d419b2f0117f30b5df42bc56852eb75c7504))
* **gui:** add phase 7a tabbed asset viewers (property/hex/info) ([#594](https://github.com/r6e/paksmith/issues/594)) ([dd4e4c4](https://github.com/r6e/paksmith/commit/dd4e4c456ae0bdbc1270200bdaac6e1b7e5e1baf))
* **gui:** add texture viewer view mode (phase 7b) ([#614](https://github.com/r6e/paksmith/issues/614)) ([ac4bd96](https://github.com/r6e/paksmith/commit/ac4bd96f68732e6c936d3b18f210283e48173134))
* **gui:** add toast notifications (phase 7c) ([#615](https://github.com/r6e/paksmith/issues/615)) ([a1389ca](https://github.com/r6e/paksmith/commit/a1389caf04d364b2b33cae5bc7991c84fbcc0fd7))
* **gui:** apply the selected profile's mappings and engine version ([#866](https://github.com/r6e/paksmith/issues/866)) ([d2ab9d4](https://github.com/r6e/paksmith/commit/d2ab9d41fb9df8091ac4d4baf1b83d390af29b5c))
* **gui:** composite an alpha checkerboard behind the texture viewer ([#761](https://github.com/r6e/paksmith/issues/761)) ([4f70604](https://github.com/r6e/paksmith/commit/4f706045622a1d7e914add8c544994b1a5519b0e))
* **gui:** phase 6 GUI shell (Iced two-pane explorer + core resolve refactor) ([#593](https://github.com/r6e/paksmith/issues/593)) ([7ae4c94](https://github.com/r6e/paksmith/commit/7ae4c944f7283aa9191e0593a622a6be5ccb57d1))
* **gui:** read the system appearance from mundy instead of dark-light ([#799](https://github.com/r6e/paksmith/issues/799)) ([20c310b](https://github.com/r6e/paksmith/commit/20c310ba8a3897b0d462517638e80734935047a3))
* **gui:** refresh the profile selector after opens and on demand ([#726](https://github.com/r6e/paksmith/issues/726)) ([393c8e6](https://github.com/r6e/paksmith/commit/393c8e688358fcca138ed6144f7843e59408549c))
* **gui:** shell chrome — console button, Ctrl+O off-macOS, live theme follow ([#736](https://github.com/r6e/paksmith/issues/736)) ([ce66557](https://github.com/r6e/paksmith/commit/ce66557762a9f06619820e2fce1ad9260c59042d))
* **gui:** show process memory usage in the status bar ([#734](https://github.com/r6e/paksmith/issues/734)) ([857317d](https://github.com/r6e/paksmith/commit/857317d916e9c5c40c77110c81654dc14c841640))
* **gui:** window the file tree, hex view and property inspector to the viewport ([#733](https://github.com/r6e/paksmith/issues/733)) ([315316a](https://github.com/r6e/paksmith/commit/315316a891f2d2d16ec6b33fc83c8feb23fa9eba))
* **profile:** consume engine_version in version-ambiguous parse gates ([#714](https://github.com/r6e/paksmith/issues/714)) ([319e3e6](https://github.com/r6e/paksmith/commit/319e3e6b2c87ea268d317b9bdb60dea1b77b2508))


### Bug Fixes

* **core:** share an object reference's name instead of copying it ([#832](https://github.com/r6e/paksmith/issues/832)) ([1101eac](https://github.com/r6e/paksmith/commit/1101eacb87deb0656fb599d236f65a495fe75709))
* **gui:** bound the Windows startup appearance read ([#858](https://github.com/r6e/paksmith/issues/858)) ([cbf9141](https://github.com/r6e/paksmith/commit/cbf914148a4dea7382800e437bc41aa5b3d57265))
* **gui:** cap each console record's bytes ([#883](https://github.com/r6e/paksmith/issues/883)) ([a3dc6a9](https://github.com/r6e/paksmith/commit/a3dc6a910dfd41d44b50c1d99b22b4d817880936)), closes [#708](https://github.com/r6e/paksmith/issues/708)
* **gui:** keep the destination's mode and a bounded temp name in export ([#862](https://github.com/r6e/paksmith/issues/862)) ([92b1a85](https://github.com/r6e/paksmith/commit/92b1a854c62044e7396a3160881ba63b322da2ba))
* **gui:** persist the archive-open failure toast until dismissed ([#760](https://github.com/r6e/paksmith/issues/760)) ([720bc82](https://github.com/r6e/paksmith/commit/720bc828def40aef9a4bf3ab07e2ff28e9f6b488))
* **gui:** seed the accent from main and take iced without its linux theme detection ([#859](https://github.com/r6e/paksmith/issues/859)) ([e185d92](https://github.com/r6e/paksmith/commit/e185d92ad2a467b2909bcae4e82c105e43797656))
* **release:** revert phantom 0.2.0 version bump back to 0.1.0 ([#475](https://github.com/r6e/paksmith/issues/475)) ([054d418](https://github.com/r6e/paksmith/commit/054d41899b2af15af44a007ece3a837c08a7841a))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * paksmith-core bumped from 0.1 to 0.2.0
  * dev-dependencies
    * paksmith-core bumped from 0.1 to 0.2.0
