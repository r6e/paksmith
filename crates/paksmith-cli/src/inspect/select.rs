//! Dotted-path navigation and export selection over the serialised inspect document (a `serde_json::Value`).

use serde_json::Value;

/// Navigate `root` by a dotted `path`, returning the located sub-value.
///
/// Each segment is either an object key or a numeric array index. Empty,
/// leading, trailing, and doubled-dot segments are skipped (lenient). On
/// failure the error names the segment that could not be resolved and the
/// full `path` for context.
pub(crate) fn navigate<'v>(root: &'v Value, path: &str) -> Result<&'v Value, String> {
    let mut cur = root;
    for seg in path.split('.').filter(|s| !s.is_empty()) {
        cur = match cur {
            Value::Object(map) => map
                .get(seg)
                .ok_or_else(|| format!("no key '{seg}' in path '{path}'"))?,
            Value::Array(arr) => {
                let idx: usize = seg.parse().map_err(|_| {
                    format!("path segment '{seg}' is not an array index in '{path}'")
                })?;
                arr.get(idx)
                    .ok_or_else(|| format!("index {idx} out of range in path '{path}'"))?
            }
            _ => {
                return Err(format!(
                    "cannot descend into scalar at '{seg}' in path '{path}'"
                ));
            }
        };
    }
    Ok(cur)
}

/// Resolve an `--export` selector against the serialized `exports` array.
/// Numeric → array index; otherwise → match `object_name`. Errors on
/// out-of-range index, unknown name, or an ambiguous (multi-match) name.
pub(crate) fn resolve_export(exports: &Value, selector: &str) -> Result<usize, String> {
    let arr = exports
        .as_array()
        .ok_or_else(|| "no exports array in document".to_string())?;
    if let Ok(idx) = selector.parse::<usize>() {
        if idx < arr.len() {
            return Ok(idx);
        }
        return Err(format!(
            "export index {idx} out of range (0..{})",
            arr.len()
        ));
    }
    let matches: Vec<usize> = arr
        .iter()
        .enumerate()
        .filter(|(_, e)| e.get("object_name").and_then(Value::as_str) == Some(selector))
        .map(|(i, _)| i)
        .collect();
    match matches.as_slice() {
        [i] => Ok(*i),
        [] => Err(format!("no export named '{selector}'")),
        many => Err(format!(
            "export name '{selector}' is ambiguous ({} matches)",
            many.len()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn doc() -> Value {
        json!({
            "schema_version": 1,
            "summary": { "guid": "abc", "name_count": 3 },
            "exports": [ { "object_name": "Root", "asset": { "Generic": { "kind": "opaque" } } } ]
        })
    }

    #[test]
    fn navigates_object_key() {
        assert_eq!(navigate(&doc(), "summary.guid").unwrap(), &json!("abc"));
    }

    #[test]
    fn navigates_array_index_and_nested() {
        assert_eq!(
            navigate(&doc(), "exports.0.object_name").unwrap(),
            &json!("Root")
        );
    }

    #[test]
    fn navigates_to_subtree() {
        assert_eq!(navigate(&doc(), "summary").unwrap(), &doc()["summary"]);
    }

    #[test]
    fn root_path_returns_whole_doc() {
        assert_eq!(navigate(&doc(), "").unwrap(), &doc());
    }

    #[test]
    fn missing_key_errors() {
        assert!(navigate(&doc(), "summary.nope").is_err());
    }

    #[test]
    fn oob_array_index_errors() {
        assert!(navigate(&doc(), "exports.9").is_err());
    }

    #[test]
    fn non_numeric_array_index_errors() {
        assert!(navigate(&doc(), "exports.x").is_err());
    }

    #[test]
    fn descend_into_scalar_errors() {
        assert!(navigate(&doc(), "schema_version.x").is_err());
    }

    fn exports() -> Value {
        json!([
            { "object_name": "Root" },
            { "object_name": "Mesh" },
            { "object_name": "Mesh" }
        ])
    }

    #[test]
    fn resolve_by_index() {
        assert_eq!(resolve_export(&exports(), "0").unwrap(), 0);
    }

    #[test]
    fn resolve_by_unique_name() {
        assert_eq!(resolve_export(&exports(), "Root").unwrap(), 0);
    }

    #[test]
    fn resolve_index_out_of_range_errors() {
        assert!(resolve_export(&exports(), "9").is_err());
    }

    #[test]
    fn resolve_unknown_name_errors() {
        assert!(resolve_export(&exports(), "Nope").is_err());
    }

    #[test]
    fn resolve_ambiguous_name_errors() {
        assert!(resolve_export(&exports(), "Mesh").is_err());
    }
}
