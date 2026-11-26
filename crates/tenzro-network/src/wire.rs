//! Decoding bytes a peer sent.
//!
//! Plain `bincode::deserialize` reads one value and ignores whatever follows
//! it, and takes input of any length. Bytes from the network are decoded here
//! instead: input longer than the frame that may carry it is refused before
//! decoding, and bytes after the value are refused, so one value has one
//! encoding. The encoding is the one `bincode::serialize` writes.
//!
//! A length prefix needs no limit of its own on this path: decoding from a
//! slice checks a string's or a byte buffer's claimed length against the
//! bytes that remain before taking any, and a sequence reserves no more
//! than serde's capped size hint before its elements are read.

use bincode::Options;
use serde::de::DeserializeOwned;

/// Decodes `bytes` from a peer as one `T`, refusing input longer than
/// `frame` bytes and bytes after the value.
pub fn decode_bounded<T: DeserializeOwned>(bytes: &[u8], frame: usize) -> bincode::Result<T> {
    if bytes.len() > frame {
        return Err(Box::new(bincode::ErrorKind::SizeLimit));
    }
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_bincode_writes_decodes() {
        let value = (7u64, vec![1u8, 2, 3], "seven".to_string());
        let bytes = bincode::serialize(&value).unwrap();
        let back: (u64, Vec<u8>, String) = decode_bounded(&bytes, bytes.len()).unwrap();
        assert_eq!(back, value);
    }

    /// Length prefixes claiming 2^64 - 1 bytes or 2^40 elements are refused
    /// for what the input lacks, with nothing reserved for the claim: either
    /// claim honoured would abort the test for want of memory.
    #[test]
    fn an_oversized_length_prefix_is_refused_without_allocating() {
        let claim = u64::MAX.to_le_bytes();
        assert!(decode_bounded::<String>(&claim, 1 << 20).is_err());
        assert!(decode_bounded::<Vec<u8>>(&claim, 1 << 20).is_err());
        let mut elements = (1u64 << 40).to_le_bytes().to_vec();
        elements.extend_from_slice(&[0; 16]);
        assert!(decode_bounded::<Vec<u64>>(&elements, 1 << 20).is_err());
        assert!(decode_bounded::<Vec<Vec<u8>>>(&elements, 1 << 20).is_err());
    }

    #[test]
    fn input_past_the_frame_or_past_the_value_is_refused() {
        let bytes = bincode::serialize(&vec![0u8; 64]).unwrap();
        let refused = decode_bounded::<Vec<u8>>(&bytes, bytes.len() - 1).unwrap_err();
        assert!(
            matches!(*refused, bincode::ErrorKind::SizeLimit),
            "{refused}"
        );
        let mut padded = bytes.clone();
        padded.push(0);
        assert!(decode_bounded::<Vec<u8>>(&padded, 1 << 20).is_err());
        assert!(bincode::deserialize::<Vec<u8>>(&padded).is_ok());
    }
}
