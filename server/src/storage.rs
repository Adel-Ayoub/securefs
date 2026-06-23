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
    use proptest::prelude::*;

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

    // A path the chokepoint accepts: rooted at /home, sane depth, no NUL byte.
    fn safe_path() -> impl Strategy<Value = String> {
        prop::collection::vec("[A-Za-z0-9._-]{1,16}", 0..=12).prop_map(|segs| {
            if segs.is_empty() {
                "/home".to_string()
            } else {
                format!("/home/{}", segs.join("/"))
            }
        })
    }

    // Safe paths plus arbitrary and hand-picked adversarial strings, to probe
    // the gate from both sides (the NUL cases the `.*` regex never emits).
    fn any_path() -> impl Strategy<Value = String> {
        let adversarial = prop::sample::select(vec![
            "/etc/passwd".to_string(),
            "/home/../etc/passwd".to_string(),
            "/home/../../root".to_string(),
            "/".to_string(),
            String::new(),
            "/homeevil".to_string(),
            "/root".to_string(),
            "/home/a\0b".to_string(),
            "../home".to_string(),
            "/home/".to_string(),
        ]);
        prop_oneof![
            safe_path(),
            adversarial,
            ".*",
            ".*".prop_map(|s| format!("/home/{s}")),
        ]
    }

    proptest! {
        // Acceptance is exactly `is_safe_path`, and every accepted path maps to a
        // 64-char lowercase-hex key with no path separators - so no input, however
        // adversarial, yields an on-disk key that could escape the storage root.
        #[test]
        fn physical_key_matches_gate_and_is_opaque(p in any_path()) {
            match physical_key(&p) {
                Ok(key) => {
                    prop_assert!(is_safe_path(&p));
                    prop_assert_eq!(key.len(), 64);
                    prop_assert!(
                        key.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    );
                }
                Err(StorageError::UnsafePath) => prop_assert!(!is_safe_path(&p)),
            }
        }

        // The chokepoint and the underlying digest are deterministic.
        #[test]
        fn physical_key_is_deterministic(p in safe_path()) {
            prop_assert_eq!(physical_key(&p).unwrap(), physical_key(&p).unwrap());
            prop_assert_eq!(path_digest(&p), path_digest(&p));
        }

        // Distinct accepted paths map to distinct keys (keyed-HMAC injectivity).
        #[test]
        fn distinct_safe_paths_get_distinct_keys(p in safe_path(), q in safe_path()) {
            prop_assume!(p != q);
            prop_assert_ne!(physical_key(&p).unwrap(), physical_key(&q).unwrap());
        }
    }
}
