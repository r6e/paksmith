//! `--export` resolution and `--path` navigation, both over the serialized
//! inspect document (a `serde_json::Value`).

use serde_json::Value;

/// Navigate `root` by a dotted `path` (object keys + numeric array indices),
/// returning the located sub-value. `Err` describes the failing segment.
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
    fn bad_array_index_errors() {
        assert!(navigate(&doc(), "exports.9").is_err());
        assert!(navigate(&doc(), "exports.x").is_err());
    }

    #[test]
    fn descend_into_scalar_errors() {
        assert!(navigate(&doc(), "schema_version.x").is_err());
    }
}
