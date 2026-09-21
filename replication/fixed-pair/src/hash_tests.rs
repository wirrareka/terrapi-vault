use super::*;
use serde::ser::{SerializeSeq, Serializer};

const ROW: &str = "a repeated row with escapes: \"\\\n and Unicode 🦀";

fn matches_buffered<T: Serialize>(value: &T) -> Result<()> {
    let expected = format!("{:x}", Sha256::digest(serde_json::to_vec(value)?));
    assert_eq!(hash(value)?, expected);
    Ok(())
}

#[test]
fn json_digest_preserves_legacy_bytes() -> Result<()> {
    assert_eq!(
        hash(&())?,
        "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"
    );
    matches_buffered(&serde_json::json!({
        "escaped": "\"\\\n\r\t\u{0000}", "unicode": "Bratislava — دبي 🦀",
        "array": [null, true, false, 0, -1], "nested": {"empty": []}
    }))?;
    matches_buffered(&(i64::MIN, u64::MAX, -0.0f64, 1e-200f64, 1e200f64))?;
    matches_buffered(&(f64::NAN, f64::INFINITY, f64::NEG_INFINITY))?;
    matches_buffered(&vec![0u8, 127, 255])?;
    matches_buffered(&crate::envelope_tests::stock_entry())?;
    Ok(())
}

struct Repeated {
    count: usize,
    fail_after: Option<usize>,
}
impl Serialize for Repeated {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.count))?;
        for n in 0..self.count {
            if self.fail_after == Some(n) {
                return Err(serde::ser::Error::custom("fixture serialization failure"));
            }
            seq.serialize_element(ROW)?;
        }
        seq.end()
    }
}

#[test]
fn generated_large_json_matches_buffered_digest() -> Result<()> {
    // Generates rows without materializing the source collection. Only the legacy
    // comparison intentionally allocates the complete serialized JSON buffer.
    matches_buffered(&Repeated {
        count: 100_000,
        fail_after: None,
    })
}

#[test]
fn serialization_failure_never_returns_a_partial_digest() {
    for fail_after in [0, 1, 4096] {
        let error = hash(&Repeated {
            count: 5000,
            fail_after: Some(fail_after),
        })
        .unwrap_err();
        assert!(error.to_string().contains("fixture serialization failure"));
    }
}

#[test]
#[ignore = "manual isolated-process memory profile; requires VESTA_HASH_PROFILE_MODE"]
fn profile_generated_json() -> Result<()> {
    let mode = std::env::var("VESTA_HASH_PROFILE_MODE")?;
    let value = Repeated {
        count: 1_000_000,
        fail_after: None,
    };
    let digest = match mode.as_str() {
        "buffered" => format!("{:x}", Sha256::digest(serde_json::to_vec(&value)?)),
        "streamed" => hash(&value)?,
        _ => return Err("unsupported hash profile mode".into()),
    };
    let bytes = 1 + value.count * (serde_json::to_vec(ROW)?.len() + 1);
    println!("mode={mode} json_bytes={bytes} sha256={digest}");
    Ok(())
}
