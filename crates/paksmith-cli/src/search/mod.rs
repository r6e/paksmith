//! Search predicate compilation + matching (pure; no I/O).

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
