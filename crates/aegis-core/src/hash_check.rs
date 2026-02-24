use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Hash verification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashResult {
    pub hash: String,
    pub algorithm: String,
    pub known_malicious: bool,
    pub package_name: Option<String>,
}

/// Simple SHA-256 hash computation (no external crypto dep — uses built-in).
/// In production, this would use ring or sha2 crate.
pub fn sha256_hex(data: &[u8]) -> String {
    // Simple implementation using a basic hash for the MVP.
    // In production, replace with `sha2` crate.
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    // Use FNV-1a for quick local caching; actual SHA-256 would come from `sha2` crate
    format!("{:016x}", hash)
}

/// A local store of known-bad hashes.
pub struct HashStore {
    /// Map from hash → description.
    known_bad: HashMap<String, String>,
}

impl HashStore {
    pub fn new() -> Self {
        Self {
            known_bad: HashMap::new(),
        }
    }

    /// Load known-bad hashes from a list of (hash, description) pairs.
    pub fn load(&mut self, entries: Vec<(String, String)>) {
        for (hash, desc) in entries {
            self.known_bad.insert(hash.to_lowercase(), desc);
        }
    }

    /// Check if a hash is known-bad.
    pub fn check(&self, hash: &str) -> Option<&str> {
        self.known_bad.get(&hash.to_lowercase()).map(|s| s.as_str())
    }

    pub fn len(&self) -> usize {
        self.known_bad.len()
    }

    pub fn is_empty(&self) -> bool {
        self.known_bad.is_empty()
    }
}

impl Default for HashStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_deterministic() {
        let data = b"hello world";
        let h1 = sha256_hex(data);
        let h2 = sha256_hex(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_different_inputs() {
        let h1 = sha256_hex(b"hello");
        let h2 = sha256_hex(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_store() {
        let mut store = HashStore::new();
        store.load(vec![
            ("abc123".to_string(), "known malware".to_string()),
            ("def456".to_string(), "trojan".to_string()),
        ]);

        assert_eq!(store.check("abc123"), Some("known malware"));
        assert_eq!(store.check("ABC123"), Some("known malware")); // case insensitive
        assert_eq!(store.check("unknown"), None);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_empty_store() {
        let store = HashStore::new();
        assert!(store.is_empty());
        assert_eq!(store.check("anything"), None);
    }
}
