//! End-to-end integration tests for the public `Vault` API.
//!
//! These exercise the crate exactly as `memento-core` and `probe-core`
//! will, using the production default KDF params only where the cost
//! is acceptable.

use std::io::Read;
use tempfile::TempDir;
use terrapi_vesta::{Error, KdfParams, Vault};

/// Fast params: full Argon2id cost is validated by the unit timing test;
/// integration tests just need the encryption path.
fn fast() -> KdfParams {
    KdfParams {
        m_cost_kib: 8 * 1024,
        t_cost: 1,
        p_cost: 1,
    }
}

#[test]
fn create_lock_open_with_correct_passphrase() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("notes.memento");

    let v = Vault::create(&path, "s3cret", fast()).unwrap();
    v.with_connection(|c| c.execute_batch("CREATE TABLE n(t TEXT); INSERT INTO n VALUES ('hi');"))
        .unwrap();
    v.lock();

    let v = Vault::open(&path, "s3cret").unwrap();
    let t: String = v
        .with_connection(|c| c.query_row("SELECT t FROM n", [], |r| r.get(0)))
        .unwrap();
    assert_eq!(t, "hi");
}

#[test]
fn open_with_wrong_passphrase_returns_wrong_passphrase_no_panic() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("notes.memento");
    Vault::create(&path, "right", fast()).unwrap().lock();

    let err = Vault::open(&path, "WRONG").unwrap_err();
    assert!(matches!(err, Error::WrongPassphrase), "got {err:?}");
}

#[test]
fn rotate_key_old_fails_new_succeeds_data_preserved() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("notes.memento");

    let mut v = Vault::create(&path, "old-pass", fast()).unwrap();
    v.with_connection(|c| {
        c.execute_batch("CREATE TABLE kv(k TEXT, v TEXT); INSERT INTO kv VALUES('a','b');")
    })
    .unwrap();
    v.rotate_key("old-pass", "new-pass").unwrap();
    v.lock();

    assert!(matches!(
        Vault::open(&path, "old-pass").unwrap_err(),
        Error::WrongPassphrase
    ));

    let v = Vault::open(&path, "new-pass").unwrap();
    let val: String = v
        .with_connection(|c| c.query_row("SELECT v FROM kv WHERE k='a'", [], |r| r.get(0)))
        .unwrap();
    assert_eq!(val, "b");
}

#[test]
fn on_disk_file_is_not_plaintext_sqlite() {
    // A plaintext SQLite DB starts with "SQLite format 3\0".
    const PLAINTEXT_MAGIC: &[u8; 16] = b"SQLite format 3\0";

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("notes.memento");
    Vault::create(&path, "pw", fast()).unwrap().lock();

    let mut f = std::fs::File::open(&path).unwrap();
    let mut header = [0u8; 16];
    f.read_exact(&mut header).unwrap();
    assert_ne!(
        &header, PLAINTEXT_MAGIC,
        "vault file must be encrypted, found plaintext SQLite header"
    );
}

#[test]
fn meta_sidecar_is_written_next_to_db() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("notes.memento");
    let v = Vault::create(&path, "pw", fast()).unwrap();
    assert!(v.meta_path().exists());
    assert!(v.meta_path().to_string_lossy().ends_with(".meta.json"));
}
