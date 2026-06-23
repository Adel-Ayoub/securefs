// Exercises the storage chokepoint (physical_key) together with the LocalFs
// blobstore: blobs round-trip, the on-disk layout carries no cleartext names,
// and out-of-home paths are refused before any I/O.

use securefs_blobstore::{Blobstore, LocalFs};
use securefs_server::storage::physical_key;

fn collect_paths(dir: &std::path::Path, out: &mut Vec<String>) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let p = entry.path();
            out.push(p.to_string_lossy().to_string());
            if p.is_dir() {
                collect_paths(&p, out);
            }
        }
    }
}

#[tokio::test]
async fn blob_round_trips_with_opaque_on_disk_layout() {
    // SAFETY: single-threaded test — no concurrent env access.
    unsafe { std::env::set_var("DB_PASS", "securefs") };

    let root = std::env::temp_dir().join(format!("securefs-storage-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let store = LocalFs::new(&root);

    let logical = "/home/alice/secret-notes.txt";
    let key = physical_key(logical).expect("safe path maps to a key");

    store.put(&key, b"ciphertext-bytes").await.expect("put");
    assert_eq!(store.get(&key).await.expect("get"), b"ciphertext-bytes");

    // No path component on disk may reveal the cleartext name or directory.
    let mut paths = Vec::new();
    collect_paths(&root, &mut paths);
    for p in &paths {
        assert!(
            !p.contains("secret-notes") && !p.contains("alice"),
            "cleartext name leaked on disk: {p}"
        );
    }

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn paths_outside_home_are_refused() {
    for bad in ["/etc/passwd", "/", "", "/root", "/homeevil", "/home/x\0y"] {
        assert!(
            physical_key(bad).is_err(),
            "path {bad:?} should be refused by the chokepoint"
        );
    }
}
