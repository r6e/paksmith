//! `FPropertyTag` wire reader.
//!
//! Phase 2b layout (UE 4.21+, `FileVersionUE4 ≥ 504`):
//!
//! ```text
//! Name:            FName (i32 index, i32 number)
//!                  → None terminator when index==0 && number==0
//! Type:            FName
//! Size:            i32   (payload bytes; 0 for BoolProperty)
//! ArrayIndex:      i32
//! [type extras]    (BoolProperty: u8 boolVal;
//!                   StructProperty: FName struct_name + [u8; 16] struct_guid;
//!                   ByteProperty|EnumProperty: FName enum_name;
//!                   ArrayProperty|SetProperty: FName inner_type;
//!                   MapProperty: FName inner_type + FName value_type)
//! HasPropertyGuid: u8
//! [PropertyGuid]:  [u8; 16] if HasPropertyGuid != 0
//! ```
//!
//! `VER_UE4_STRUCT_GUID_IN_PROPERTY_TAG` (441) and
//! `VER_UE4_PROPERTY_GUID_IN_PROPERTY_TAG` (503) are both below
//! Phase 2a's floor of 504, so both are always present.

use std::io::Read;
use std::sync::{Arc, LazyLock};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::asset::AssetContext;
use crate::error::{AssetParseFault, AssetWireField, BoundsUnit, PaksmithError};

use super::{read_fname_pair, unexpected_eof};

/// Shared empty `Arc<str>` for default / unused string fields on
/// `PropertyTag` and the dispatched-extras fall-through. `Arc::from("")`
/// allocates a fresh refcount header per call (no interning in
/// stdlib); for `read_tag` that's 4-5 throwaway allocs per
/// `FPropertyTag` header (most type-specific extras leave 3-4 of the
/// six string fields unset). `Arc::clone(&EMPTY_ARC_STR)` is an
/// atomic refcount bump instead. Surfaced by the #365 R1 panel
/// (simplifier conf 90, perf conf 80, architect conf 70).
pub(super) static EMPTY_ARC_STR: LazyLock<Arc<str>> = LazyLock::new(|| Arc::from(""));

/// Maximum allowed size for a single property value payload.
/// Caps the per-tag discard budget so a single `Unknown`-type skip
/// cannot drain more than 16 MiB from the reader. (The previous
/// `Vec`-based skip path allocated that buffer; #366 switched to
/// `io::copy` → `io::sink` so the cap now bounds the I/O budget
/// rather than the heap.)
pub const MAX_PROPERTY_TAG_SIZE: i32 = 16 * 1024 * 1024;

/// Decoded `FPropertyTag` header.
///
/// All type-specific fields (`struct_name`, `enum_name`, etc.) are
/// populated during tag reading regardless of whether the type is
/// handled — Phase 2c's container readers rely on `inner_type`
/// already being resolved.
///
/// String fields are `Arc<str>` rather than `String` (#365): the wire
/// source is the `Arc<str>`-backed FName pool, so a refcount-bump
/// clone propagates the name into the tag without a heap allocation.
/// `clone()` on a `PropertyTag` then refcount-bumps the fields too —
/// matters on the per-element hot path for `Array<Struct>` containers
/// where each element clones the inner tag.
#[derive(Debug, Clone)]
pub struct PropertyTag {
    /// Resolved property name (FName base + optional `_N` suffix).
    pub(crate) name: Arc<str>,
    /// Resolved type name (e.g. `"BoolProperty"`, `"IntProperty"`).
    pub(crate) type_name: Arc<str>,
    /// Serialized value size in bytes (0 for `BoolProperty`).
    pub size: i32,
    /// Array element index (0 for non-array properties).
    pub array_index: i32,
    /// Boolean value for `BoolProperty`; `false` otherwise.
    pub bool_val: bool,
    /// Struct type name for `StructProperty`; empty otherwise.
    pub(crate) struct_name: Arc<str>,
    /// Struct type GUID for `StructProperty`; zeroed otherwise.
    pub struct_guid: [u8; 16],
    /// Enum type name for `ByteProperty` / `EnumProperty`; empty otherwise.
    pub(crate) enum_name: Arc<str>,
    /// Inner element type for `ArrayProperty` / `SetProperty` /
    /// `MapProperty` key.
    pub(crate) inner_type: Arc<str>,
    /// Value type for `MapProperty`; empty otherwise.
    pub(crate) value_type: Arc<str>,
    /// Optional per-property GUID (`HasPropertyGuid` byte was non-zero).
    pub guid: Option<[u8; 16]>,
    /// The parsed `FPropertyTypeName` tree for UE5 ≥ 1012 tags
    /// (`(name, inner_count)` pre-order nodes); `None` for the legacy
    /// tag shape. Carried so the array-of-struct reader can derive the
    /// elided inner tag's struct name from the outer tag (#643).
    pub(crate) type_name_tree: Option<Arc<[TypeNameNode]>>,
}

/// One pre-order node of a UE5 ≥ 1012 `FPropertyTypeName` tree. #643.
#[derive(Debug, Clone)]
pub(crate) struct TypeNameNode {
    /// Resolved FName for this node.
    pub(crate) name: Arc<str>,
    /// Number of direct child parameters following this node.
    pub(crate) inner_count: i32,
}

impl PropertyTag {
    /// Resolved property name (FName base + optional `_N` suffix).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Resolved type name (e.g. `"BoolProperty"`, `"IntProperty"`).
    #[must_use]
    pub fn type_name(&self) -> &str {
        &self.type_name
    }
    /// Struct type name for `StructProperty`; empty for other types.
    #[must_use]
    pub fn struct_name(&self) -> &str {
        &self.struct_name
    }
    /// Enum type name for `ByteProperty` / `EnumProperty`; empty otherwise.
    #[must_use]
    pub fn enum_name(&self) -> &str {
        &self.enum_name
    }
    /// Inner element type for `ArrayProperty` / `SetProperty` /
    /// `MapProperty` key.
    #[must_use]
    pub fn inner_type(&self) -> &str {
        &self.inner_type
    }
    /// Value type for `MapProperty`; empty otherwise.
    #[must_use]
    pub fn value_type(&self) -> &str {
        &self.value_type
    }
}

impl PropertyTag {
    /// The struct name of an elided `Array<Struct>` inner tag (UE5 ≥
    /// 1012): the outer tag's tree at `ArrayProperty → param0
    /// (StructProperty) → param0`. Empty when the tag has no tree or
    /// the tree lacks the parameter (mirrors CUE4Parse's null
    /// `InnerTypeData` fall-through — the element parse then runs
    /// without a typed-struct dispatch). #643.
    pub(crate) fn tree_inner_struct_name(&self) -> Arc<str> {
        let Some(tree) = &self.type_name_tree else {
            return Arc::clone(&EMPTY_ARC_STR);
        };
        let Some(inner) = type_name_parameter(tree, 0, 0) else {
            return Arc::clone(&EMPTY_ARC_STR);
        };
        let Some(sn) = type_name_parameter(tree, inner, 0) else {
            return Arc::clone(&EMPTY_ARC_STR);
        };
        Arc::clone(&tree[sn].name)
    }
}

/// Test-only construction of a `PropertyTag` from raw field values.
/// Gated behind `__test_utils` because `PropertyTag` is otherwise
/// `pub(crate)`-constructed via the wire-format parser; tests that
/// need to drive readers with synthetic tags use this builder.
///
/// `Default` is implemented and exposed under the same feature flag
/// so callers can `..PropertyTag::default()` spread only the fields
/// they care about.
///
/// **Caution:** prefer the [`PropertyTag::for_test`] +`.with_*`
/// builder chain for the string fields (`name`, `enum_name`,
/// `struct_name`, `inner_type`, `value_type`). The builder hides
/// the `&str → Arc<str>` conversion from callers — keeping the
/// builder route insulates tests from any future representation
/// change to these fields. (#365 migrated them from `String` to
/// `Arc<str>` already; the builder shape made that flip invisible
/// to test sites.)
#[cfg(any(test, feature = "__test_utils"))]
impl Default for PropertyTag {
    fn default() -> Self {
        Self {
            name: Arc::clone(&EMPTY_ARC_STR),
            type_name: Arc::clone(&EMPTY_ARC_STR),
            size: 0,
            array_index: 0,
            bool_val: false,
            struct_name: Arc::clone(&EMPTY_ARC_STR),
            struct_guid: [0u8; 16],
            enum_name: Arc::clone(&EMPTY_ARC_STR),
            inner_type: Arc::clone(&EMPTY_ARC_STR),
            value_type: Arc::clone(&EMPTY_ARC_STR),
            guid: None,
            type_name_tree: None,
        }
    }
}

#[cfg(any(test, feature = "__test_utils"))]
impl PropertyTag {
    /// Test-only builder. Sets `name`, `type_name`, and `size`;
    /// defaults every other field. Chain `.with_*` setters for
    /// additional fields.
    ///
    /// The setter family has two rationales:
    /// - String fields (`with_name`, `with_struct_name`,
    ///   `with_enum_name`, `with_inner_type`, `with_value_type`) sit
    ///   between the test sites and the field types so issue #365's
    ///   `String → Arc<str>` migration is invisible to callers.
    /// - Non-string ergonomic setters (`with_bool_val` for the
    ///   `BoolProperty`-only inline payload) just avoid post-
    ///   construction field-assignment ceremony.
    #[must_use]
    pub fn for_test(name: &str, type_name: &str, size: i32) -> Self {
        Self {
            name: Arc::from(name),
            type_name: Arc::from(type_name),
            size,
            ..Self::default()
        }
    }

    /// Test-only chainable setter for `type_name_tree` (UE5 ≥ 1012
    /// shape). Builds nodes from `(name, inner_count)` pairs. #643.
    #[must_use]
    pub fn with_type_name_tree(mut self, nodes: &[(&str, i32)]) -> Self {
        self.type_name_tree = Some(
            nodes
                .iter()
                .map(|(n, c)| TypeNameNode {
                    name: Arc::from(*n),
                    inner_count: *c,
                })
                .collect(),
        );
        self
    }

    /// Test-only chainable setter for `struct_name`.
    #[must_use]
    pub fn with_struct_name(mut self, struct_name: &str) -> Self {
        self.struct_name = Arc::from(struct_name);
        self
    }

    /// Test-only chainable setter for `enum_name`.
    #[must_use]
    pub fn with_enum_name(mut self, enum_name: &str) -> Self {
        self.enum_name = Arc::from(enum_name);
        self
    }

    /// Test-only chainable setter for `inner_type`.
    #[must_use]
    pub fn with_inner_type(mut self, inner_type: &str) -> Self {
        self.inner_type = Arc::from(inner_type);
        self
    }

    /// Test-only chainable setter for `value_type`.
    #[must_use]
    pub fn with_value_type(mut self, value_type: &str) -> Self {
        self.value_type = Arc::from(value_type);
        self
    }

    /// Test-only chainable setter for `bool_val` (the
    /// `BoolProperty`-only inline payload that lives on the tag
    /// header rather than the value body).
    #[must_use]
    pub fn with_bool_val(mut self, bool_val: bool) -> Self {
        self.bool_val = bool_val;
        self
    }

    /// Test-only chainable setter for `name`. Lets a helper-factory-
    /// built tag (which seeds `name` from a defaulted source like
    /// `make_array_tag("StructProperty", ...)`) override the property
    /// name without dropping back to direct field mutation.
    #[must_use]
    pub fn with_name(mut self, name: &str) -> Self {
        self.name = Arc::from(name);
        self
    }
}

/// Resolve a wire-format `(index, number)` FName pair to a `String`.
///
/// `number <= 0` → no suffix; `number > 0` → `"Base_N"` where
/// `N = number − 1` (UE stores the suffix offset by `+1` so that `0`
/// means "no suffix" without losing the `_0` case).
///
/// Intentionally distinct from [`NameTable::resolve`](crate::asset::NameTable::resolve):
/// the header-side resolve takes `u32`s and renders OOB as a tolerant
/// `<oob:{index}>` placeholder, because at header-read time an OOB
/// index is at worst a Phase-2a parser bug surfacing visibly. At
/// property-tag-iteration time an `i32::MIN` `nameIndex` is real
/// attacker-controllable input that must produce a structured error
/// (`PackageIndexUnderflow`) rather than a placeholder string.
///
/// # Errors
///
/// - [`AssetParseFault::PackageIndexUnderflow`] for `index < 0`.
/// - [`AssetParseFault::PackageIndexOob`] for `index` past the name table.
pub fn resolve_fname(
    index: i32,
    number: i32,
    ctx: &AssetContext,
    asset_path: &str,
    field: AssetWireField,
) -> crate::Result<Arc<str>> {
    if index < 0 {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::PackageIndexUnderflow { field },
        });
    }
    #[allow(
        clippy::cast_sign_loss,
        reason = "the `index < 0` branch above returns; the cast is non-negative"
    )]
    let idx = index as u32;
    let fname = ctx
        .names
        .get(idx)
        .ok_or_else(|| PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::PackageIndexOob {
                field,
                index: idx,
                table_size: u32::try_from(ctx.names.names.len()).unwrap_or(u32::MAX),
            },
        })?;
    if number <= 0 {
        // Refcount bump — no heap allocation; the FName pool's
        // backing `Arc<str>` is shared across every resolution of
        // the same wire index.
        Ok(fname.clone_arc())
    } else {
        // Suffixed names (`Foo_1`, `Bar_42`) are not in the FName
        // pool; one allocation per suffix.
        Ok(Arc::from(format!("{}_{}", fname.as_str(), number - 1)))
    }
}

/// Read one `FPropertyTag` from `reader`, resolving FNames via `ctx`.
///
/// Returns `Ok(None)` when the "None" terminator is reached (either
/// `name_index == 0 && name_number == 0` or the resolved name equals
/// `"None"`).
///
/// # Errors
///
/// - [`AssetParseFault::NegativeValue`] with `field: AssetWireField::PropertyTagSize`
///   if `Size < 0`. Reuses the shared signed-negative variant Phase 2a uses for
///   `NameCount`/`ImportCount`/`ExportSerialSize`.
/// - [`AssetParseFault::BoundsExceeded`] with `field: AssetWireField::PropertyTagSize`,
///   `unit: BoundsUnit::Bytes` if `Size > MAX_PROPERTY_TAG_SIZE`. Reuses the
///   shared cap-overflow variant Phase 2a uses for `TotalHeaderSize`/`NameOffset`.
/// - [`AssetParseFault::PackageIndexUnderflow`] / [`AssetParseFault::PackageIndexOob`]
///   for out-of-range FName indexes.
/// - [`AssetParseFault::UnexpectedEof`] on short reads.
///
/// The `Read`-only bound is intentional — `read_tag` does sequential
/// `read_*` calls only; no `stream_position`/`seek`. The caller
/// (`read_properties` in `mod.rs`) is `Read + Seek` and bubbles the
/// stronger bound up to where it's used.
#[allow(
    clippy::too_many_lines,
    reason = "FPropertyTag's wire layout reads sequentially with type-specific extras dispatched \
              by name; splitting would obscure the byte-by-byte mirror of CUE4Parse's \
              FPropertyTag.Serialize"
)]
pub fn read_tag<R: Read>(
    reader: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<Option<PropertyTag>> {
    // Read the Name pair manually (not via `read_fname_pair`) so the
    // index==0 && number==0 None-terminator probe runs before the
    // PackageIndex* resolve step — a literal `(0, 0)` pair must NOT
    // emit an OOB error when the name table happens to be empty.
    let name_index = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagName))?;
    let name_number = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagName))?;
    if name_index == 0 && name_number == 0 {
        return Ok(None);
    }
    let name = resolve_fname(
        name_index,
        name_number,
        ctx,
        asset_path,
        AssetWireField::PropertyTagName,
    )?;
    // Defensive fallback for exotic encoders that spell "None"
    // differently (e.g. number > 0 but the base name == "None").
    if name.as_ref() == "None" {
        return Ok(None);
    }

    // UE5 ≥ 1012 (`PROPERTY_TAG_COMPLETE_TYPE_NAME`): everything after
    // the Name is a different wire shape — dispatch to the tree-based
    // reader. #643.
    if ctx
        .version
        .ue5_at_least(crate::asset::version::VER_UE5_PROPERTY_TAG_COMPLETE_TYPE_NAME)
    {
        return read_tag_complete_type_name(reader, ctx, asset_path, name).map(Some);
    }

    let type_name = read_fname_pair(reader, ctx, asset_path, AssetWireField::PropertyTagType)?;

    let size = read_validated_size(reader, asset_path)?;

    let array_index = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagArrayIndex))?;

    // Type-specific extras. Default to the shared `EMPTY_ARC_STR`
    // (refcount bump, not heap alloc) — the matched arm below
    // overwrites at most one or two of the five fields.
    let mut bool_val = false;
    let mut struct_name: Arc<str> = Arc::clone(&EMPTY_ARC_STR);
    let mut struct_guid = [0u8; 16];
    let mut enum_name: Arc<str> = Arc::clone(&EMPTY_ARC_STR);
    let mut inner_type: Arc<str> = Arc::clone(&EMPTY_ARC_STR);
    let mut value_type: Arc<str> = Arc::clone(&EMPTY_ARC_STR);

    match type_name.as_ref() {
        "BoolProperty" => {
            let bv = reader
                .read_u8()
                .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagBoolVal))?;
            bool_val = bv != 0;
        }
        "StructProperty" => {
            struct_name = read_fname_pair(
                reader,
                ctx,
                asset_path,
                AssetWireField::PropertyTagStructName,
            )?;
            reader
                .read_exact(&mut struct_guid)
                .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagStructGuid))?;
        }
        "ByteProperty" | "EnumProperty" => {
            enum_name =
                read_fname_pair(reader, ctx, asset_path, AssetWireField::PropertyTagEnumName)?;
        }
        "ArrayProperty" | "SetProperty" => {
            inner_type = read_fname_pair(
                reader,
                ctx,
                asset_path,
                AssetWireField::PropertyTagInnerType,
            )?;
        }
        "MapProperty" => {
            inner_type = read_fname_pair(
                reader,
                ctx,
                asset_path,
                AssetWireField::PropertyTagInnerType,
            )?;
            value_type = read_fname_pair(
                reader,
                ctx,
                asset_path,
                AssetWireField::PropertyTagValueType,
            )?;
        }
        // OptionalProperty (an FName inner type in the oracle's legacy
        // constructor) is deliberately absent: it ships with UE 5.4
        // (object 1012), which always takes the tree branch — reaching
        // here with OptionalProperty means version-inconsistent crafted
        // input, surfaced downstream by the cursor invariant.
        _ => {}
    }

    let has_guid = reader
        .read_u8()
        .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagHasGuid))?;
    let guid = if has_guid != 0 {
        let mut g = [0u8; 16];
        reader
            .read_exact(&mut g)
            .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagGuid))?;
        Some(g)
    } else {
        None
    };

    if ctx
        .version
        .ue5_at_least(crate::asset::version::VER_UE5_PROPERTY_TAG_EXTENSION)
    {
        read_tag_extension(reader, asset_path)?;
    }

    Ok(Some(PropertyTag {
        name,
        type_name,
        size,
        array_index,
        bool_val,
        struct_name,
        struct_guid,
        enum_name,
        inner_type,
        value_type,
        guid,
        type_name_tree: None,
    }))
}

/// Read + validate the tag's `i32 Size` (negative → fault; capped by
/// [`MAX_PROPERTY_TAG_SIZE`]). Shared by the legacy and UE5 ≥ 1012 tag
/// shapes. #643.
fn read_validated_size<R: Read>(reader: &mut R, asset_path: &str) -> crate::Result<i32> {
    let size = reader
        .read_i32::<LittleEndian>()
        .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagSize))?;
    if size < 0 {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::NegativeValue {
                field: AssetWireField::PropertyTagSize,
                value: i64::from(size),
            },
        });
    }
    if size > MAX_PROPERTY_TAG_SIZE {
        #[allow(
            clippy::cast_sign_loss,
            reason = "both casts are post the `size < 0` rejection above; \
                      MAX_PROPERTY_TAG_SIZE is a positive compile-time const"
        )]
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::BoundsExceeded {
                field: AssetWireField::PropertyTagSize,
                value: size as u64,
                limit: MAX_PROPERTY_TAG_SIZE as u64,
                unit: BoundsUnit::Bytes,
            },
        });
    }
    Ok(size)
}

/// Cap on `FPropertyTypeName` tree nodes per tag (UE5 ≥ 1012). Real
/// property types nest a handful of nodes (a `Map<Struct, Array<Struct>>`
/// with modules is ~9); 64 is generous against legitimate content while
/// bounding an adversarial `inner_count` chain. #643.
const MAX_TYPE_NAME_NODES: usize = 64;

/// Read the UE5 ≥ 1012 `FPropertyTypeName` tree: pre-order
/// `(FName, i32 inner_count)` nodes, terminated by a remaining-counter
/// reaching zero (no total-count prefix on the wire — CUE4Parse
/// `FPropertyTypeNameNode`). Negative `inner_count` and trees larger
/// than [`MAX_TYPE_NAME_NODES`] fail closed. #643.
fn read_type_name_tree<R: Read>(
    reader: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<Vec<TypeNameNode>> {
    let mut nodes: Vec<TypeNameNode> = Vec::new();
    // i64: 64 iterations × inner_count ≤ i32::MAX cannot overflow.
    let mut remaining: i64 = 1;
    while remaining > 0 {
        if nodes.len() == MAX_TYPE_NAME_NODES {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::PropertyTagType,
                    value: (MAX_TYPE_NAME_NODES as u64) + 1,
                    limit: MAX_TYPE_NAME_NODES as u64,
                    unit: BoundsUnit::Items,
                },
            });
        }
        let name = read_fname_pair(reader, ctx, asset_path, AssetWireField::PropertyTagType)?;
        let inner_count = reader
            .read_i32::<LittleEndian>()
            .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagType))?;
        if inner_count < 0 {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::PropertyTagType,
                    value: i64::from(inner_count),
                },
            });
        }
        remaining += i64::from(inner_count) - 1;
        nodes.push(TypeNameNode { name, inner_count });
    }
    Ok(nodes)
}

/// Index of the subtree rooted just past `root`'s `param`-th parameter
/// — CUE4Parse `GetParameter` semantics: parameters are the pre-order
/// siblings after `root`, each skipping its own subtree. `None` when
/// the parameter doesn't exist. #643.
fn type_name_parameter(nodes: &[TypeNameNode], root: usize, param: usize) -> Option<usize> {
    let root_node = nodes.get(root)?;
    if param >= usize::try_from(root_node.inner_count).ok()? {
        return None;
    }
    let mut idx = root.checked_add(1)?;
    for _ in 0..param {
        idx = skip_subtree(nodes, idx)?;
    }
    if idx < nodes.len() { Some(idx) } else { None }
}

/// Index just past the subtree rooted at `idx` (pre-order walk with a
/// remaining-counter). `None` if the tree is malformed/truncated —
/// unreachable for trees produced by `read_type_name_tree`, which
/// closes the counter before returning. #643.
fn skip_subtree(nodes: &[TypeNameNode], idx: usize) -> Option<usize> {
    let mut end = idx;
    let mut rem: i64 = 1;
    while rem > 0 {
        rem += i64::from(nodes.get(end)?.inner_count) - 1;
        end = end.checked_add(1)?;
    }
    Some(end)
}

/// `u8 EPropertyTagFlags` bits (UE5 ≥ 1012). #643.
const TAG_FLAG_HAS_ARRAY_INDEX: u8 = 0x01;
const TAG_FLAG_HAS_PROPERTY_GUID: u8 = 0x02;
const TAG_FLAG_HAS_PROPERTY_EXTENSIONS: u8 = 0x04;
const TAG_FLAG_HAS_BINARY_OR_NATIVE_SERIALIZE: u8 = 0x08;
const TAG_FLAG_BOOL_TRUE: u8 = 0x10;
const TAG_FLAG_SKIPPED_SERIALIZE: u8 = 0x20;
const TAG_FLAG_KNOWN_MASK: u8 = TAG_FLAG_HAS_ARRAY_INDEX
    | TAG_FLAG_HAS_PROPERTY_GUID
    | TAG_FLAG_HAS_PROPERTY_EXTENSIONS
    | TAG_FLAG_HAS_BINARY_OR_NATIVE_SERIALIZE
    | TAG_FLAG_BOOL_TRUE
    | TAG_FLAG_SKIPPED_SERIALIZE;

/// The UE5 ≥ 1012 (`PROPERTY_TAG_COMPLETE_TYPE_NAME`) tag shape,
/// after the (already-read) Name: `FPropertyTypeName` tree → `i32 Size`
/// → `u8 EPropertyTagFlags` → flag-gated `ArrayIndex` / `PropertyGuid`
/// / extension byte(s). Gone from the wire vs the legacy shape: the
/// standalone `ArrayIndex`, the `BoolProperty` payload byte
/// (`BoolTrue` flag replaces it), the `StructGuid`, and the
/// guid-presence byte. Type extras (struct/enum/inner/value names)
/// come from the tree per CUE4Parse `FPropertyTagData`; the module
/// path nodes nested under them are not surfaced (paksmith carries no
/// module field). Unknown flag bits fail closed. #643.
fn read_tag_complete_type_name<R: Read>(
    reader: &mut R,
    ctx: &AssetContext,
    asset_path: &str,
    name: Arc<str>,
) -> crate::Result<PropertyTag> {
    let nodes = read_type_name_tree(reader, ctx, asset_path)?;
    let type_name = Arc::clone(&nodes[0].name);

    let mut struct_name: Arc<str> = Arc::clone(&EMPTY_ARC_STR);
    let mut enum_name: Arc<str> = Arc::clone(&EMPTY_ARC_STR);
    let mut inner_type: Arc<str> = Arc::clone(&EMPTY_ARC_STR);
    let mut value_type: Arc<str> = Arc::clone(&EMPTY_ARC_STR);
    match type_name.as_ref() {
        "StructProperty" => {
            if let Some(i) = type_name_parameter(&nodes, 0, 0) {
                struct_name = Arc::clone(&nodes[i].name);
            }
        }
        "ByteProperty" | "EnumProperty" => {
            if let Some(i) = type_name_parameter(&nodes, 0, 0) {
                enum_name = Arc::clone(&nodes[i].name);
            }
        }
        "ArrayProperty" | "SetProperty" | "OptionalProperty" => {
            if let Some(i) = type_name_parameter(&nodes, 0, 0) {
                inner_type = Arc::clone(&nodes[i].name);
            }
        }
        "MapProperty" => {
            if let Some(i) = type_name_parameter(&nodes, 0, 0) {
                inner_type = Arc::clone(&nodes[i].name);
            }
            if let Some(i) = type_name_parameter(&nodes, 0, 1) {
                value_type = Arc::clone(&nodes[i].name);
            }
        }
        _ => {}
    }

    let size = read_validated_size(reader, asset_path)?;

    let flags = reader
        .read_u8()
        .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagFlags))?;
    if flags & !TAG_FLAG_KNOWN_MASK != 0 {
        return Err(PaksmithError::UnsupportedFeature {
            context: format!(
                "EPropertyTagFlags {flags:#04x} in {asset_path}: bits outside the known \
                 0x3F mask have no defined wire shape"
            ),
        });
    }
    let bool_val = flags & TAG_FLAG_BOOL_TRUE != 0;
    let array_index = if flags & TAG_FLAG_HAS_ARRAY_INDEX != 0 {
        reader
            .read_i32::<LittleEndian>()
            .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagArrayIndex))?
    } else {
        0
    };
    let guid = if flags & TAG_FLAG_HAS_PROPERTY_GUID != 0 {
        let mut g = [0u8; 16];
        reader
            .read_exact(&mut g)
            .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagGuid))?;
        Some(g)
    } else {
        None
    };
    if flags & TAG_FLAG_HAS_PROPERTY_EXTENSIONS != 0 {
        read_tag_extension(reader, asset_path)?;
    }

    Ok(PropertyTag {
        name,
        type_name,
        size,
        array_index,
        bool_val,
        struct_name,
        struct_guid: [0u8; 16],
        enum_name,
        inner_type,
        value_type,
        guid,
        type_name_tree: Some(Arc::from(nodes)),
    })
}

/// `u8 EPropertyTagExtension` flags byte (UE5 ≥ 1011), shared by the
/// legacy tag tail and (via `HasPropertyExtensions`) the 1012 tag
/// shape. Known bits: `OverridableInformation` (0x02) — its payload
/// (`u8 EOverriddenPropertyOperation` + a **bool32**
/// `bExperimentalOverridableLogic`, CUE4Parse `Ar.ReadBoolean()` =
/// 4-byte int; 5 bytes total — NOT the 1-byte payload of the
/// per-object serialization-control byte) is consumed and discarded,
/// mirroring CUE4Parse's skip; the bool32 is 0/1-validated per house
/// style. Any OTHER bit set (incl. `ReserveForFutureUse` 0x01, which
/// marks a further extension group of unknown wire shape) fails
/// closed — unknown trailing bytes would desync every subsequent
/// tag. #643.
fn read_tag_extension<R: Read>(reader: &mut R, asset_path: &str) -> crate::Result<()> {
    const OVERRIDABLE_INFORMATION: u8 = 0x02;
    let ext = reader
        .read_u8()
        .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagExtension))?;
    if ext & !OVERRIDABLE_INFORMATION != 0 {
        return Err(crate::PaksmithError::UnsupportedFeature {
            context: format!(
                "EPropertyTagExtension flags {ext:#04x} in {asset_path}: only \
                 OverridableInformation (0x02) has a known wire shape; other bits \
                 mark extension groups whose size is undefined"
            ),
        });
    }
    if ext & OVERRIDABLE_INFORMATION != 0 {
        let _override_operation = reader
            .read_u8()
            .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagExtension))?;
        // bool32, 0/1-validated; EOF keeps the tag reader's typed-EOF
        // contract rather than read_bool32's raw Io propagation.
        let experimental = reader
            .read_i32::<LittleEndian>()
            .map_err(|_| unexpected_eof(asset_path, AssetWireField::PropertyTagExtension))?;
        if !matches!(experimental, 0 | 1) {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::InvalidBool32 {
                    field: AssetWireField::PropertyTagExtension,
                    observed: experimental,
                },
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::property::test_utils::{
        make_ctx, make_ctx_with_version_and_names, write_fname,
    };
    use std::io::Cursor;

    /// Bytes of a minimal IntProperty tag through the guid-presence
    /// byte (legacy tail shape) — the shared prefix for the UE5 ≥ 1011
    /// extension-byte tests. Names: 1 = "Score", 2 = "IntProperty".
    fn int_tag_prefix() -> Vec<u8> {
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 0);
        write_fname(&mut buf, 2, 0);
        buf.extend_from_slice(&4i32.to_le_bytes()); // size
        buf.extend_from_slice(&0i32.to_le_bytes()); // array_index
        buf.push(0); // HasPropertyGuid = 0
        buf
    }

    fn ue5_1012_ctx(names: &[&str]) -> crate::asset::AssetContext {
        make_ctx_with_version_and_names(522, Some(1012), names)
    }

    /// Write one `(FName index, inner_count)` tree node. #643.
    fn write_node(buf: &mut Vec<u8>, name_index: i32, inner_count: i32) {
        write_fname(buf, name_index, 0);
        buf.extend_from_slice(&inner_count.to_le_bytes());
    }

    /// UE5 ≥ 1012: single-node tree + flags 0x00 — no ArrayIndex, no
    /// guid byte on the wire; sentinel lands right after. #643.
    #[test]
    fn tag_1012_int_property_minimal() {
        use byteorder::{LittleEndian, ReadBytesExt};
        let ctx = ue5_1012_ctx(&["None", "Score", "IntProperty"]);
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 0); // Name = Score
        write_node(&mut buf, 2, 0); // tree: IntProperty(0)
        buf.extend_from_slice(&4i32.to_le_bytes()); // Size
        buf.push(0x00); // flags
        buf.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let mut cur = Cursor::new(&buf[..]);
        let tag = read_tag(&mut cur, &ctx, "x.uasset").unwrap().unwrap();
        assert_eq!(tag.name(), "Score");
        assert_eq!(tag.type_name(), "IntProperty");
        assert_eq!(tag.size, 4);
        assert_eq!(tag.array_index, 0);
        assert_eq!(tag.guid, None);
        assert!(tag.type_name_tree.is_some());
        assert_eq!(cur.read_u32::<LittleEndian>().unwrap(), 0xDEAD_BEEF);
    }

    /// Struct param0 = struct name (its param0 = module, not surfaced);
    /// Map param0/param1 = key/value; Array param0 = inner. #643.
    #[test]
    fn tag_1012_tree_maps_type_extras() {
        // StructProperty(1) -> Vector(1) -> CoreUObject(0)
        let names = &["None", "P", "StructProperty", "Vector", "CoreUObject"];
        let ctx = ue5_1012_ctx(names);
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 0);
        write_node(&mut buf, 2, 1);
        write_node(&mut buf, 3, 1);
        write_node(&mut buf, 4, 0);
        buf.extend_from_slice(&12i32.to_le_bytes());
        buf.push(0x00);
        let tag = read_tag(&mut Cursor::new(&buf[..]), &ctx, "x")
            .unwrap()
            .unwrap();
        assert_eq!(tag.type_name(), "StructProperty");
        assert_eq!(tag.struct_name(), "Vector");
        assert_eq!(tag.struct_guid, [0u8; 16]);

        // MapProperty(2) -> IntProperty(0), StrProperty(0)
        let names = &["None", "M", "MapProperty", "IntProperty", "StrProperty"];
        let ctx = ue5_1012_ctx(names);
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 0);
        write_node(&mut buf, 2, 2);
        write_node(&mut buf, 3, 0);
        write_node(&mut buf, 4, 0);
        buf.extend_from_slice(&8i32.to_le_bytes());
        buf.push(0x00);
        let tag = read_tag(&mut Cursor::new(&buf[..]), &ctx, "x")
            .unwrap()
            .unwrap();
        assert_eq!(tag.inner_type(), "IntProperty");
        assert_eq!(tag.value_type(), "StrProperty");

        // ArrayProperty(1) -> StructProperty(1) -> Vector(1) -> Core(0):
        // inner_type from param0; the elided struct name is reachable
        // through the retained tree (Array param0's param0).
        let names = &[
            "None",
            "A",
            "ArrayProperty",
            "StructProperty",
            "Vector",
            "Core",
        ];
        let ctx = ue5_1012_ctx(names);
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 0);
        write_node(&mut buf, 2, 1);
        write_node(&mut buf, 3, 1);
        write_node(&mut buf, 4, 1);
        write_node(&mut buf, 5, 0);
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.push(0x00);
        let tag = read_tag(&mut Cursor::new(&buf[..]), &ctx, "x")
            .unwrap()
            .unwrap();
        assert_eq!(tag.inner_type(), "StructProperty");
        let tree = tag.type_name_tree.as_ref().unwrap();
        let inner = type_name_parameter(tree, 0, 0).unwrap();
        let struct_name = type_name_parameter(tree, inner, 0).unwrap();
        assert_eq!(tree[struct_name].name.as_ref(), "Vector");
    }

    /// Flag-gated fields: BoolTrue sets bool_val (no payload byte);
    /// HasArrayIndex / HasPropertyGuid / HasPropertyExtensions read
    /// their payloads in order. #643.
    #[test]
    fn tag_1012_flags_gate_payloads() {
        use byteorder::{LittleEndian, ReadBytesExt};
        let ctx = ue5_1012_ctx(&["None", "B", "BoolProperty"]);
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 0);
        write_node(&mut buf, 2, 0);
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.push(0x10 | 0x01 | 0x02 | 0x04); // BoolTrue+ArrayIndex+Guid+Extensions
        buf.extend_from_slice(&7i32.to_le_bytes()); // ArrayIndex
        buf.extend_from_slice(&[0xAB; 16]); // guid
        buf.push(0x00); // extension byte: NoExtension
        buf.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let mut cur = Cursor::new(&buf[..]);
        let tag = read_tag(&mut cur, &ctx, "x").unwrap().unwrap();
        assert!(tag.bool_val);
        assert_eq!(tag.array_index, 7);
        assert_eq!(tag.guid, Some([0xAB; 16]));
        assert_eq!(cur.read_u32::<LittleEndian>().unwrap(), 0xDEAD_BEEF);
        // HasBinaryOrNativeSerialize / SkippedSerialize are known,
        // payload-free bits — accepted.
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 0);
        write_node(&mut buf, 2, 0);
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.push(0x08 | 0x20);
        let tag = read_tag(&mut Cursor::new(&buf[..]), &ctx, "x")
            .unwrap()
            .unwrap();
        assert!(!tag.bool_val);
    }

    /// Unknown flag bits (0x40/0x80) fail closed. #643.
    #[test]
    fn tag_1012_unknown_flag_bits_fail_closed() {
        let ctx = ue5_1012_ctx(&["None", "P", "IntProperty"]);
        for bad in [0x40u8, 0x80, 0xC0] {
            let mut buf = Vec::new();
            write_fname(&mut buf, 1, 0);
            write_node(&mut buf, 2, 0);
            buf.extend_from_slice(&4i32.to_le_bytes());
            buf.push(bad);
            let err = read_tag(&mut Cursor::new(&buf[..]), &ctx, "x").unwrap_err();
            assert!(
                matches!(err, crate::PaksmithError::UnsupportedFeature { .. }),
                "flags {bad:#04x} must fail closed, got {err:?}"
            );
        }
    }

    /// Adversarial trees: negative inner_count faults; a
    /// remaining-counter chain past MAX_TYPE_NAME_NODES faults before
    /// unbounded reads. #643.
    #[test]
    fn tag_1012_tree_guards() {
        let ctx = ue5_1012_ctx(&["None", "P", "IntProperty"]);
        // Negative inner_count.
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 0);
        write_node(&mut buf, 2, -1);
        let err = read_tag(&mut Cursor::new(&buf[..]), &ctx, "x").unwrap_err();
        assert!(matches!(
            err,
            crate::PaksmithError::AssetParse {
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::PropertyTagType,
                    ..
                },
                ..
            }
        ));
        // Node-count cap: every node claims one more child.
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 0);
        for _ in 0..=MAX_TYPE_NAME_NODES {
            write_node(&mut buf, 2, 1);
        }
        let err = read_tag(&mut Cursor::new(&buf[..]), &ctx, "x").unwrap_err();
        assert!(matches!(
            err,
            crate::PaksmithError::AssetParse {
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::PropertyTagType,
                    unit: BoundsUnit::Items,
                    ..
                },
                ..
            }
        ));
    }

    /// 1011 (extension byte, legacy shape) still applies when the
    /// version is exactly 1011 — the 1012 branch must not swallow it;
    /// and at 1012 the legacy trailing extension read must NOT run
    /// (flags govern it). #643.
    #[test]
    fn tag_1012_none_terminator_still_short_circuits() {
        let ctx = ue5_1012_ctx(&["None"]);
        let buf: Vec<u8> = vec![0, 0, 0, 0, 0, 0, 0, 0];
        let tag = read_tag(&mut Cursor::new(&buf[..]), &ctx, "x").unwrap();
        assert!(tag.is_none());
    }

    fn ue5_1011_ctx() -> crate::asset::AssetContext {
        make_ctx_with_version_and_names(522, Some(1011), &["None", "Score", "IntProperty"])
    }

    /// UE5 ≥ 1011: a NoExtension (0x00) flags byte after the guid
    /// block is consumed — the sentinel that follows stays unread. #643.
    #[test]
    fn extension_byte_no_extension_consumed_at_1011() {
        use byteorder::{LittleEndian, ReadBytesExt};
        let ctx = ue5_1011_ctx();
        let mut buf = int_tag_prefix();
        buf.push(0x00); // EPropertyTagExtension::NoExtension
        buf.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // sentinel
        let mut cur = Cursor::new(&buf[..]);
        let tag = read_tag(&mut cur, &ctx, "x.uasset").unwrap().unwrap();
        assert_eq!(tag.name(), "Score");
        assert_eq!(cur.read_u32::<LittleEndian>().unwrap(), 0xDEAD_BEEF);
    }

    /// UE5 ≥ 1011: OverridableInformation (0x02) carries a 5-byte
    /// payload (u8 op + bool32), consumed and discarded. #643.
    #[test]
    fn extension_byte_overridable_information_skips_payload() {
        use byteorder::{LittleEndian, ReadBytesExt};
        let ctx = ue5_1011_ctx();
        let mut buf = int_tag_prefix();
        buf.push(0x02); // OverridableInformation
        buf.push(0x01); // OverrideOperation
        buf.extend_from_slice(&1u32.to_le_bytes()); // bExperimentalOverridableLogic (bool32)
        buf.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // sentinel
        let mut cur = Cursor::new(&buf[..]);
        let tag = read_tag(&mut cur, &ctx, "x.uasset").unwrap().unwrap();
        assert_eq!(tag.name(), "Score");
        assert_eq!(cur.read_u32::<LittleEndian>().unwrap(), 0xDEAD_BEEF);
    }

    /// Unknown extension bits (incl. ReserveForFutureUse 0x01, which
    /// marks a further group of UNKNOWN size) fail closed. #643.
    #[test]
    fn extension_byte_unknown_bits_fail_closed() {
        let ctx = ue5_1011_ctx();
        for bad in [0x01u8, 0x04, 0x80, 0x03] {
            let mut buf = int_tag_prefix();
            buf.push(bad);
            let err = read_tag(&mut Cursor::new(&buf[..]), &ctx, "x.uasset").unwrap_err();
            assert!(
                matches!(err, crate::PaksmithError::UnsupportedFeature { .. }),
                "flags {bad:#04x} must fail closed, got {err:?}"
            );
        }
    }

    /// A truncated extension byte / payload is a structured EOF. #643.
    #[test]
    fn extension_byte_truncation_is_structured_eof() {
        let ctx = ue5_1011_ctx();
        // Missing the flags byte entirely.
        let buf = int_tag_prefix();
        let err = read_tag(&mut Cursor::new(&buf[..]), &ctx, "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            crate::PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::UnexpectedEof {
                    field: AssetWireField::PropertyTagExtension,
                },
                ..
            }
        ));
        // Flags byte present but payload truncated (op byte only, no
        // bool32).
        let mut buf = int_tag_prefix();
        buf.push(0x02);
        buf.push(0x01); // only 1 of 5 payload bytes
        let err = read_tag(&mut Cursor::new(&buf[..]), &ctx, "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            crate::PaksmithError::AssetParse {
                fault: crate::error::AssetParseFault::UnexpectedEof {
                    field: AssetWireField::PropertyTagExtension,
                },
                ..
            }
        ));
    }

    /// The OverridableInformation payload's bool32 is 0/1-validated —
    /// garbage fails as InvalidBool32, not silent acceptance. #643.
    #[test]
    fn extension_byte_payload_bool32_validated() {
        let ctx = ue5_1011_ctx();
        let mut buf = int_tag_prefix();
        buf.push(0x02);
        buf.push(0x00); // OverrideOperation
        buf.extend_from_slice(&7i32.to_le_bytes()); // bool32 = 7: invalid
        let err = read_tag(&mut Cursor::new(&buf[..]), &ctx, "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            crate::PaksmithError::AssetParse {
                fault: AssetParseFault::InvalidBool32 {
                    field: AssetWireField::PropertyTagExtension,
                    observed: 7,
                },
                ..
            }
        ));
    }

    /// UE5 = 1010 must NOT read an extension byte (regression pin for
    /// the gate boundary). #643.
    #[test]
    fn no_extension_byte_below_1011() {
        use byteorder::{LittleEndian, ReadBytesExt};
        let ctx =
            make_ctx_with_version_and_names(522, Some(1010), &["None", "Score", "IntProperty"]);
        let mut buf = int_tag_prefix();
        buf.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // sentinel directly
        let mut cur = Cursor::new(&buf[..]);
        let tag = read_tag(&mut cur, &ctx, "x.uasset").unwrap().unwrap();
        assert_eq!(tag.name(), "Score");
        assert_eq!(cur.read_u32::<LittleEndian>().unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn none_terminator_returns_none() {
        let ctx = make_ctx(&["None"]);
        let buf: Vec<u8> = vec![0, 0, 0, 0, 0, 0, 0, 0];
        let tag = read_tag(&mut Cursor::new(&buf[..]), &ctx, "x.uasset").unwrap();
        assert!(tag.is_none());
    }

    #[test]
    fn bool_property_tag_decoded() {
        let ctx = make_ctx(&["None", "bEnabled", "BoolProperty"]);
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 0);
        write_fname(&mut buf, 2, 0);
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.push(1u8);
        buf.push(0u8);
        let tag = read_tag(&mut Cursor::new(&buf[..]), &ctx, "x.uasset")
            .unwrap()
            .unwrap();
        assert_eq!(tag.name.as_ref(), "bEnabled");
        assert_eq!(tag.type_name.as_ref(), "BoolProperty");
        assert_eq!(tag.size, 0);
        assert!(tag.bool_val);
        assert!(tag.guid.is_none());
    }

    #[test]
    fn int_property_tag_decoded() {
        let ctx = make_ctx(&["None", "MaxHP", "IntProperty"]);
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 0);
        write_fname(&mut buf, 2, 0);
        buf.extend_from_slice(&4i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.push(0u8);
        let tag = read_tag(&mut Cursor::new(&buf[..]), &ctx, "x.uasset")
            .unwrap()
            .unwrap();
        assert_eq!(tag.name.as_ref(), "MaxHP");
        assert_eq!(tag.type_name.as_ref(), "IntProperty");
        assert_eq!(tag.size, 4);
    }

    #[test]
    fn negative_size_is_rejected() {
        let ctx = make_ctx(&["None", "Foo", "IntProperty"]);
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 0);
        write_fname(&mut buf, 2, 0);
        buf.extend_from_slice(&(-1i32).to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.push(0u8);
        let err = read_tag(&mut Cursor::new(&buf[..]), &ctx, "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::NegativeValue {
                    field: AssetWireField::PropertyTagSize,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn size_exceeding_cap_is_rejected() {
        let ctx = make_ctx(&["None", "Foo", "StrProperty"]);
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 0);
        write_fname(&mut buf, 2, 0);
        buf.extend_from_slice(&(MAX_PROPERTY_TAG_SIZE + 1).to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.push(0u8);
        let err = read_tag(&mut Cursor::new(&buf[..]), &ctx, "x.uasset").unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::AssetParse {
                fault: AssetParseFault::BoundsExceeded {
                    field: AssetWireField::PropertyTagSize,
                    unit: BoundsUnit::Bytes,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn name_suffix_number_appended() {
        let ctx = make_ctx(&["None", "Foo", "IntProperty"]);
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 2);
        write_fname(&mut buf, 2, 0);
        buf.extend_from_slice(&4i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.push(0u8);
        let tag = read_tag(&mut Cursor::new(&buf[..]), &ctx, "x.uasset")
            .unwrap()
            .unwrap();
        assert_eq!(tag.name.as_ref(), "Foo_1");
    }

    #[test]
    fn struct_property_tag_reads_struct_name_and_guid() {
        let ctx = make_ctx(&["None", "Transform", "StructProperty"]);
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 0);
        write_fname(&mut buf, 2, 0);
        buf.extend_from_slice(&60i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        write_fname(&mut buf, 1, 0);
        buf.extend_from_slice(&[0xAB; 16]);
        buf.push(0u8);
        let tag = read_tag(&mut Cursor::new(&buf[..]), &ctx, "x.uasset")
            .unwrap()
            .unwrap();
        assert_eq!(tag.struct_name.as_ref(), "Transform");
        assert_eq!(tag.struct_guid, [0xABu8; 16]);
    }

    #[test]
    fn property_guid_decoded_when_present() {
        let ctx = make_ctx(&["None", "Count", "IntProperty"]);
        let mut buf = Vec::new();
        write_fname(&mut buf, 1, 0);
        write_fname(&mut buf, 2, 0);
        buf.extend_from_slice(&4i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.push(1u8);
        buf.extend_from_slice(&[0x11; 16]);
        let tag = read_tag(&mut Cursor::new(&buf[..]), &ctx, "x.uasset")
            .unwrap()
            .unwrap();
        assert_eq!(tag.guid, Some([0x11u8; 16]));
    }
}
