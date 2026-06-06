//! Lowercase-hex encode/decode shared by the sidecar (`meta`) and the key
//! slots (`keyslot`). Kept in one place so the two callers cannot drift.

/// Lowercase hex encoding of a byte slice.
#[must_use]
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decode a lowercase/uppercase hex string. Returns `None` on odd length or a
/// non-hex digit.
#[must_use]
pub(crate) fn decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips() {
        let b = [0x00u8, 0x0f, 0xa5, 0xff, 0x10];
        assert_eq!(decode(&encode(&b)).unwrap(), b);
    }

    #[test]
    fn rejects_odd_and_non_hex() {
        assert!(decode("abc").is_none());
        assert!(decode("zz").is_none());
    }
}
