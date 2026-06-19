//! Search predicate compilation + matching (pure; no I/O).

use paksmith_core::container::EntryMetadata;

use crate::commands::search::SearchArgs;

/// Extension of a basename, lowercased — `None` for no-extension or a
/// leading-dot dotfile (matches 4a `extract`'s `classify` semantics).
#[allow(dead_code)]
fn extension_of(basename: &str) -> Option<String> {
    basename
        .rfind('.')
        .filter(|&i| i > 0)
        .map(|i| basename[i + 1..].to_ascii_lowercase())
}

/// Compiled, AND-combined search predicates. Construct via [`Self::from_args`].
#[allow(dead_code)]
pub(crate) struct Predicates {
    types: Vec<String>, // lowercased extensions; empty = any
    name: Option<glob::Pattern>,
    regex: Option<regex::Regex>,
    min_size: Option<u64>,
    max_size: Option<u64>,
}

impl std::fmt::Debug for Predicates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Predicates")
            .field("types", &self.types)
            .field("name", &self.name.as_ref().map(glob::Pattern::as_str))
            .field("regex", &self.regex.as_ref().map(regex::Regex::as_str))
            .field("min_size", &self.min_size)
            .field("max_size", &self.max_size)
            .finish()
    }
}

#[allow(dead_code)]
impl Predicates {
    /// Compile/parse from CLI args. `Err((arg, reason))` names the offending
    /// flag so the caller can build a `PaksmithError::InvalidArgument`.
    pub(crate) fn from_args(args: &SearchArgs) -> Result<Self, (&'static str, String)> {
        let types = args.r#type.iter().map(|t| t.to_ascii_lowercase()).collect();

        let name = match &args.name {
            Some(g) => Some(glob::Pattern::new(g).map_err(|e| ("--name", e.to_string()))?),
            None => None,
        };
        let regex = match &args.regex {
            Some(r) => Some(regex::Regex::new(r).map_err(|e| ("--regex", e.to_string()))?),
            None => None,
        };
        let min_size = match &args.min_size {
            Some(s) => Some(parse_size(s).map_err(|e| ("--min-size", e))?),
            None => None,
        };
        let max_size = match &args.max_size {
            Some(s) => Some(parse_size(s).map_err(|e| ("--max-size", e))?),
            None => None,
        };
        if let (Some(min), Some(max)) = (min_size, max_size)
            && min > max
        {
            return Err((
                "--min-size",
                format!("--min-size {min} exceeds --max-size {max}"),
            ));
        }
        Ok(Self {
            types,
            name,
            regex,
            min_size,
            max_size,
        })
    }

    /// True iff `e` satisfies every supplied predicate (AND). Pure; no I/O.
    pub(crate) fn matches(&self, e: &EntryMetadata) -> bool {
        let path = e.path();
        let basename = path.rsplit('/').next().unwrap_or(path);

        if !self.types.is_empty() {
            let Some(ext) = extension_of(basename) else {
                return false;
            };
            if !self.types.contains(&ext) {
                return false;
            }
        }
        if let Some(g) = &self.name
            && !g.matches(basename)
        {
            return false;
        }
        if let Some(re) = &self.regex
            && !re.is_match(path)
        {
            return false;
        }
        let size = e.uncompressed_size();
        if self.min_size.is_some_and(|min| size < min) {
            return false;
        }
        if self.max_size.is_some_and(|max| size > max) {
            return false;
        }
        true
    }
}

/// Parse a human-readable size into bytes. Accepts a bare integer (bytes),
/// decimal units `KB`/`MB`/`GB`/`TB` (powers of 1000), and binary units
/// `KiB`/`MiB`/`GiB`/`TiB` (powers of 1024). Case-insensitive; an optional
/// space is allowed before the unit. Integers only (no decimals).
#[allow(dead_code)]
pub(crate) fn parse_size(s: &str) -> Result<u64, String> {
    let t = s.trim();
    if t.is_empty() {
        return Err("empty size".to_string());
    }
    // The numeric prefix is leading ASCII digits; the rest is the unit.
    let split = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
    let (num_str, unit_raw) = t.split_at(split);
    if num_str.is_empty() {
        return Err(format!("size '{s}' has no numeric value"));
    }
    let unit = unit_raw.trim().to_ascii_lowercase();
    let multiplier: u64 = match unit.as_str() {
        "" | "b" => 1,
        "kb" => 1_000,
        "mb" => 1_000_000,
        "gb" => 1_000_000_000,
        "tb" => 1_000_000_000_000,
        "kib" => 1 << 10,
        "mib" => 1 << 20,
        "gib" => 1 << 30,
        "tib" => 1 << 40,
        other => return Err(format!("size '{s}' has unknown unit '{other}'")),
    };
    let value: u64 = num_str
        .parse()
        .map_err(|_| format!("size '{s}' has an invalid number '{num_str}'"))?;
    value
        .checked_mul(multiplier)
        .ok_or_else(|| format!("size '{s}' overflows u64"))
}

#[cfg(test)]
mod parse_size_tests {
    use super::*;

    #[test]
    fn bare_integer_is_bytes() {
        assert_eq!(parse_size("1048576").unwrap(), 1_048_576);
        assert_eq!(parse_size("0").unwrap(), 0);
    }

    #[test]
    fn decimal_units_are_powers_of_1000() {
        assert_eq!(parse_size("1KB").unwrap(), 1_000);
        assert_eq!(parse_size("1MB").unwrap(), 1_000_000);
        assert_eq!(parse_size("2GB").unwrap(), 2_000_000_000);
        assert_eq!(parse_size("1TB").unwrap(), 1_000_000_000_000);
    }

    #[test]
    fn binary_units_are_powers_of_1024() {
        assert_eq!(parse_size("1KiB").unwrap(), 1_024);
        assert_eq!(parse_size("1MiB").unwrap(), 1_048_576);
        assert_eq!(parse_size("1GiB").unwrap(), 1 << 30);
        assert_eq!(parse_size("1TiB").unwrap(), 1u64 << 40);
    }

    #[test]
    fn case_and_space_insensitive() {
        assert_eq!(parse_size("1 mb").unwrap(), 1_000_000);
        assert_eq!(parse_size("512kib").unwrap(), 512 * 1024);
        assert_eq!(parse_size("1B").unwrap(), 1);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse_size("").is_err());
        assert!(parse_size("MB").is_err()); // no number
        assert!(parse_size("1.5MB").is_err()); // decimals not supported
        assert!(parse_size("1ZB").is_err()); // unknown unit
        assert!(parse_size("abc").is_err());
    }

    #[test]
    fn overflow_errors() {
        assert!(parse_size("99999999999999999999TiB").is_err());
    }

    #[test]
    fn decimal_and_binary_kilo_differ() {
        assert_eq!(parse_size("1kb").unwrap(), 1_000);
        assert_eq!(parse_size("1kib").unwrap(), 1_024);
    }
}

#[cfg(test)]
mod predicate_tests {
    use super::*;
    use paksmith_core::container::{EntryFlags, EntryMetadata};

    fn entry(path: &str, uncompressed: u64) -> EntryMetadata {
        EntryMetadata::new(
            path.to_string(),
            uncompressed, // compressed size (irrelevant here)
            uncompressed, // uncompressed size
            EntryFlags::NONE,
        )
    }

    fn args() -> crate::commands::search::SearchArgs {
        // Build via the public fields; all-None/empty = match-all.
        crate::commands::search::SearchArgs {
            pak: std::path::PathBuf::new(),
            r#type: vec![],
            name: None,
            regex: None,
            min_size: None,
            max_size: None,
        }
    }

    #[test]
    fn empty_predicates_match_all() {
        let p = Predicates::from_args(&args()).unwrap();
        assert!(p.matches(&entry("Game/Maps/Hero.uasset", 10)));
        assert!(p.matches(&entry("Config/Game.ini", 10)));
    }

    #[test]
    fn type_matches_extension_case_insensitive_or_within() {
        let mut a = args();
        a.r#type = vec!["uasset".into(), "umap".into()];
        let p = Predicates::from_args(&a).unwrap();
        assert!(p.matches(&entry("A.uasset", 1)));
        assert!(p.matches(&entry("B.UMAP", 1))); // case-insensitive
        assert!(!p.matches(&entry("C.ini", 1)));
        assert!(!p.matches(&entry("noext", 1)));
        assert!(!p.matches(&entry("Game/.uasset", 1))); // leading-dot dotfile = no ext
    }

    #[test]
    fn name_globs_basename() {
        let mut a = args();
        a.name = Some("Hero*".into());
        let p = Predicates::from_args(&a).unwrap();
        assert!(p.matches(&entry("Game/Maps/Hero.uasset", 1))); // basename match
        assert!(!p.matches(&entry("Game/Maps/Villain.uasset", 1)));
    }

    #[test]
    fn regex_matches_full_path_unanchored() {
        let mut a = args();
        a.regex = Some(r"Maps/.*\.uasset$".into());
        let p = Predicates::from_args(&a).unwrap();
        assert!(p.matches(&entry("Game/Maps/Hero.uasset", 1)));
        assert!(!p.matches(&entry("Game/UI/Button.uasset", 1)));
    }

    #[test]
    fn size_bounds_are_inclusive_on_uncompressed() {
        let mut a = args();
        a.min_size = Some("100".into());
        a.max_size = Some("200".into());
        let p = Predicates::from_args(&a).unwrap();
        assert!(!p.matches(&entry("a", 99)));
        assert!(p.matches(&entry("a", 100))); // inclusive
        assert!(p.matches(&entry("a", 200))); // inclusive
        assert!(!p.matches(&entry("a", 201)));
    }

    #[test]
    fn predicates_and_combine() {
        let mut a = args();
        a.r#type = vec!["uasset".into()];
        a.name = Some("Hero*".into());
        a.min_size = Some("50".into());
        let p = Predicates::from_args(&a).unwrap();
        assert!(p.matches(&entry("Game/Hero.uasset", 60)));
        assert!(!p.matches(&entry("Game/Hero.uasset", 10))); // fails size
        assert!(!p.matches(&entry("Game/Hero.ini", 60))); // fails type
        assert!(!p.matches(&entry("Game/Villain.uasset", 60))); // fails name
    }

    #[test]
    fn from_args_rejects_bad_inputs() {
        let mut bad_glob = args();
        bad_glob.name = Some("[".into());
        assert_eq!(Predicates::from_args(&bad_glob).unwrap_err().0, "--name");

        let mut bad_re = args();
        bad_re.regex = Some("(".into());
        assert_eq!(Predicates::from_args(&bad_re).unwrap_err().0, "--regex");

        let mut bad_size = args();
        bad_size.min_size = Some("1ZB".into());
        assert_eq!(
            Predicates::from_args(&bad_size).unwrap_err().0,
            "--min-size"
        );

        let mut inverted = args();
        inverted.min_size = Some("10".into());
        inverted.max_size = Some("5".into());
        assert_eq!(
            Predicates::from_args(&inverted).unwrap_err().0,
            "--min-size"
        );
    }
}
