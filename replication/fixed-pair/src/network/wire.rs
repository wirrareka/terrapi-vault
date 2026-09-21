//! One bounded logical JSON message, split into canonical chunks on one TLS stream.
use super::*;

const MAGIC: [u8; 4] = *b"VST3";
pub const MAX_MESSAGE: usize = 16 * MAX_FRAME;

struct BoundedBody(Vec<u8>);
impl Write for BoundedBody {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_MESSAGE - self.0.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "message too large",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn write_frame<T: Serialize>(stream: &mut impl Write, value: &T) -> Result<()> {
    // Reject over-limit serialization before sending any request bytes.
    let mut body = BoundedBody(Vec::new());
    serde_json::to_writer(&mut body, value)?;
    stream.write_all(&MAGIC)?;
    stream.write_all(&(body.0.len() as u32).to_be_bytes())?;
    stream.write_all(&Sha256::digest(&body.0))?;
    for chunk in body.0.chunks(MAX_FRAME) {
        stream.write_all(&(chunk.len() as u32).to_be_bytes())?;
        stream.write_all(chunk)?;
    }
    stream.flush()?;
    Ok(())
}

pub(super) fn read_frame<T: serde::de::DeserializeOwned>(stream: &mut impl Read) -> Result<T> {
    let mut magic = [0; 4];
    stream.read_exact(&mut magic)?;
    ensure(magic == MAGIC, "unsupported wire format")?;
    let mut header = [0; 4];
    stream.read_exact(&mut header)?;
    let total = u32::from_be_bytes(header) as usize;
    ensure(total > 0 && total <= MAX_MESSAGE, "invalid message length")?;
    let mut digest = [0; 32];
    stream.read_exact(&mut digest)?;
    // Grow only as validated chunks arrive, not from an untrusted total alone.
    let mut body = Vec::new();
    while body.len() < total {
        stream.read_exact(&mut header)?;
        let size = u32::from_be_bytes(header) as usize;
        ensure(
            size == MAX_FRAME.min(total - body.len()),
            "invalid chunk length",
        )?;
        let offset = body.len();
        body.resize(offset + size, 0);
        stream.read_exact(&mut body[offset..])?;
    }
    ensure(fingerprint(&body) == digest, "message checksum mismatch")?;
    Ok(serde_json::from_slice(&body)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_small_boundary_and_multiple_chunks() {
        for size in [0, MAX_FRAME - 2, MAX_FRAME - 1, 2 * MAX_FRAME + 17] {
            let value = "x".repeat(size);
            let mut wire = Vec::new();
            write_frame(&mut wire, &value).unwrap();
            assert_eq!(read_frame::<String>(&mut wire.as_slice()).unwrap(), value);
            let mut offset = 40;
            while offset < wire.len() {
                let n = u32::from_be_bytes(wire[offset..offset + 4].try_into().unwrap()) as usize;
                assert!(n > 0 && n <= MAX_FRAME);
                offset += 4 + n;
            }
            assert_eq!(offset, wire.len());
        }
    }

    #[test]
    fn rejects_invalid_totals_chunks_checksums_and_truncation() {
        let mut valid = Vec::new();
        write_frame(&mut valid, &"x".repeat(MAX_FRAME + 8)).unwrap();
        for total in [0, (MAX_MESSAGE + 1) as u32, u32::MAX] {
            let mut wire = valid.clone();
            wire[4..8].copy_from_slice(&total.to_be_bytes());
            assert!(read_frame::<String>(&mut wire.as_slice()).is_err());
        }
        for size in [0, 1, (MAX_FRAME + 1) as u32] {
            let mut wire = valid.clone();
            wire[40..44].copy_from_slice(&size.to_be_bytes());
            assert!(read_frame::<String>(&mut wire.as_slice()).is_err());
        }
        for length in [0, 4, 8, 39, 43, MAX_FRAME + 44, valid.len() - 1] {
            assert!(read_frame::<String>(&mut &valid[..length]).is_err());
        }
        valid[44] ^= 1;
        assert!(read_frame::<String>(&mut valid.as_slice()).is_err());
    }

    #[test]
    fn rejects_reordered_chunks_and_valid_checksum_invalid_json() {
        let value = format!("{}{}", "a".repeat(MAX_FRAME), "b".repeat(MAX_FRAME));
        let mut wire = Vec::new();
        write_frame(&mut wire, &value).unwrap();
        let second = 44 + MAX_FRAME + 4;
        for i in 0..MAX_FRAME {
            wire.swap(44 + i, second + i);
        }
        assert!(read_frame::<String>(&mut wire.as_slice()).is_err());
        let mut wire = Vec::from(MAGIC);
        wire.extend_from_slice(&1u32.to_be_bytes());
        wire.extend_from_slice(&Sha256::digest(b"!"));
        wire.extend_from_slice(&1u32.to_be_bytes());
        wire.push(b'!');
        assert!(read_frame::<String>(&mut wire.as_slice()).is_err());
    }
}
