//! Static name-keyed tables.

use std::collections::HashMap;

/// A static name-keyed table.
pub(crate) struct NameRegistry<V> {
    entries: HashMap<&'static str, V>,
    longest_key: usize,
}

impl<V> NameRegistry<V> {
    /// Builds the table from `entries`.
    #[must_use]
    pub(crate) fn new(entries: HashMap<&'static str, V>) -> Self {
        let longest_key = entries.keys().map(|key| key.len()).max().unwrap_or(0);
        Self {
            entries,
            longest_key,
        }
    }

    /// The value `name` keys, or `None` without hashing `name` when it is
    /// longer than every key.
    #[must_use]
    pub(crate) fn get(&self, name: &str) -> Option<&V> {
        if name.len() > self.longest_key {
            return None;
        }
        #[cfg(test)]
        NAME_REGISTRY_PROBES.with(|probes| probes.update(|n| n + 1));
        self.entries.get(name)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(crate) fn contains_key(&self, name: &str) -> bool {
        self.get(name).is_some()
    }
}

#[cfg(test)]
thread_local! {
    /// Lookups that reached a [`NameRegistry`]'s table on this thread.
    static NAME_REGISTRY_PROBES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// [`NameRegistry`] table probes made on this thread so far.
#[cfg(test)]
pub(crate) fn name_registry_probes() -> u64 {
    NAME_REGISTRY_PROBES.with(std::cell::Cell::get)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> NameRegistry<u8> {
        NameRegistry::new(HashMap::from([("ab", 1), ("abc", 2)]))
    }

    #[test]
    fn a_name_resolves_up_to_the_longest_key() {
        let registry = registry();
        assert_eq!(registry.get("abc"), Some(&2));
        assert_eq!(registry.get("ab"), Some(&1));
        assert_eq!(registry.get("abx"), None);
        assert_eq!(registry.get("abcd"), None);
    }

    #[test]
    fn a_name_longer_than_every_key_skips_the_probe() {
        let registry = registry();
        let probes_for = |name: &str| {
            let before = name_registry_probes();
            let _ = registry.get(name);
            name_registry_probes() - before
        };
        assert_eq!(probes_for("abc"), 1);
        assert_eq!(probes_for("zz"), 1);
        assert_eq!(probes_for("abcd"), 0);
    }
}
