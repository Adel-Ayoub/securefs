use thiserror::Error;

use crate::dao::path_digest;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("path is outside the permitted area")]
    UnsafePath,
}

// Check that a resolved path is safely within /home and contains no dangerous bytes.
pub fn is_safe_path(path: &str) -> bool {
    let under_home = path == "/home" || path.starts_with("/home/");
    let no_null = !path.contains('\0');
    let depth = path.split('/').filter(|s| !s.is_empty()).count();
    let sane_depth = depth <= 64;
    under_home && no_null && sane_depth
}

// The single chokepoint for all blob I/O: validate a logical path, then map it
// to an opaque physical blob key. Reuses the keyed path_digest so the on-disk
// name reveals nothing about the logical path. Every blob operation must route
// through here so validation can never be skipped.
pub fn physical_key(path: &str) -> Result<String, StorageError> {
    if !is_safe_path(path) {
        return Err(StorageError::UnsafePath);
    }
    Ok(hex::encode(path_digest(path)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_path_maps_to_64_hex() {
        let key = physical_key("/home/alice/notes.txt").unwrap();
        assert_eq!(key.len(), 64);
        assert!(key.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn mapping_is_deterministic() {
        let a = physical_key("/home/alice/notes.txt").unwrap();
        let b = physical_key("/home/alice/notes.txt").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_paths_get_distinct_keys() {
        let a = physical_key("/home/alice/a").unwrap();
        let b = physical_key("/home/alice/b").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn key_is_the_hex_path_digest() {
        let p = "/home/alice/notes.txt";
        assert_eq!(physical_key(p).unwrap(), hex::encode(path_digest(p)));
    }

    #[test]
    fn unsafe_paths_are_rejected() {
        for bad in ["/etc/passwd", "/", "", "/root", "/homeevil", "/home/x\0y"] {
            assert!(
                matches!(physical_key(bad), Err(StorageError::UnsafePath)),
                "path {bad:?} should be rejected"
            );
        }
    }
}
