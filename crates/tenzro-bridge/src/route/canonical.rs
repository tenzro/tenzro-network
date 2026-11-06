//! Strict canonical decoding.
//!
//! Every inbound bridge payload is read through a [`Reader`]. Each read is
//! bounds-checked, so a truncated payload is an error, never a short read.
//! Each primitive has exactly one accepted encoding: ABI words must carry
//! zero padding, ABI offsets must point at the next tail in order, Borsh
//! lengths must fit what is left. [`Reader::finish`] refuses any byte left
//! over. A payload either decodes exactly or is rejected; nothing is parsed
//! on a best-effort basis.

use crate::error::{BridgeError, Result};

fn malformed(what: impl Into<String>) -> BridgeError {
    BridgeError::InvalidParameter(format!("malformed bridge payload: {}", what.into()))
}

/// A cursor over one payload. See the module docs.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// A reader at the start of `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes consumed so far.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Refuse the payload unless every byte was consumed.
    pub fn finish(self) -> Result<()> {
        if self.pos != self.buf.len() {
            return Err(malformed(format!(
                "{} trailing bytes after the message",
                self.buf.len() - self.pos
            )));
        }
        Ok(())
    }

    /// The next `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.remaining() {
            return Err(malformed(format!(
                "truncated: needed {n} bytes at offset {}, {} left",
                self.pos,
                self.remaining()
            )));
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    /// A fixed-size array.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    /// One byte.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Little-endian u32.
    pub fn u32_le(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    /// Little-endian u64.
    pub fn u64_le(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    /// Big-endian u64.
    pub fn u64_be(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    /// Big-endian u16.
    pub fn u16_be(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    /// Big-endian u32.
    pub fn u32_be(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    /// Little-endian u128.
    pub fn u128_le(&mut self) -> Result<u128> {
        Ok(u128::from_le_bytes(self.array()?))
    }

    /// A BCS length (ULEB128, minimal, at most u32::MAX) of at most `max`.
    pub fn uleb128(&mut self, max: usize) -> Result<usize> {
        let mut v: u64 = 0;
        for i in 0..5 {
            let b = self.u8()?;
            v |= u64::from(b & 0x7f) << (7 * i);
            if b & 0x80 == 0 {
                if b == 0 && i > 0 {
                    return Err(malformed("non-minimal ULEB128 length"));
                }
                if v > u64::from(u32::MAX) || v as usize > max {
                    return Err(malformed(format!("length {v} exceeds {max}")));
                }
                return Ok(v as usize);
            }
        }
        Err(malformed("ULEB128 length too long"))
    }

    /// A BCS byte vector of at most `max` bytes.
    pub fn bcs_bytes(&mut self, max: usize) -> Result<&'a [u8]> {
        let len = self.uleb128(max)?;
        self.take(len)
    }

    /// Big-endian u128.
    pub fn u128_be(&mut self) -> Result<u128> {
        Ok(u128::from_be_bytes(self.array()?))
    }

    /// A 256-bit little-endian amount that must fit in u128.
    pub fn u256_le_as_u128(&mut self) -> Result<u128> {
        let word: [u8; 32] = self.array()?;
        if word[16..].iter().any(|b| *b != 0) {
            return Err(malformed("amount does not fit in 128 bits"));
        }
        let mut low = [0u8; 16];
        low.copy_from_slice(&word[..16]);
        Ok(u128::from_le_bytes(low))
    }

    /// A Borsh byte vector (u32 little-endian length) of at most `max` bytes.
    pub fn borsh_bytes(&mut self, max: usize) -> Result<Vec<u8>> {
        let len = self.u32_le()? as usize;
        if len > max {
            return Err(malformed(format!("field of {len} bytes exceeds {max}")));
        }
        Ok(self.take(len)?.to_vec())
    }

    /// A Borsh vector length of at most `max` items.
    pub fn borsh_len(&mut self, max: usize) -> Result<usize> {
        let len = self.u32_le()? as usize;
        if len > max {
            return Err(malformed(format!("{len} items exceed {max}")));
        }
        Ok(len)
    }

    /// A u32 big-endian length-prefixed byte string of at most `max` bytes.
    pub fn be_bytes(&mut self, max: usize) -> Result<&'a [u8]> {
        let len = u32::from_be_bytes(self.array()?) as usize;
        if len > max {
            return Err(malformed(format!("field of {len} bytes exceeds {max}")));
        }
        self.take(len)
    }

    /// A u16 big-endian length-prefixed UTF-8 string of at most `max` bytes.
    pub fn be_str(&mut self, max: usize) -> Result<String> {
        let len = u16::from_be_bytes(self.array()?) as usize;
        if len > max {
            return Err(malformed(format!("string of {len} bytes exceeds {max}")));
        }
        String::from_utf8(self.take(len)?.to_vec()).map_err(|_| malformed("string is not UTF-8"))
    }

    /// One 32-byte ABI word.
    pub fn word(&mut self) -> Result<[u8; 32]> {
        self.array()
    }

    /// An ABI unsigned integer of `bits` bits: every higher byte must be zero.
    fn abi_uint(&mut self, bits: usize) -> Result<[u8; 32]> {
        let word = self.word()?;
        if word[..32 - bits / 8].iter().any(|b| *b != 0) {
            return Err(malformed(format!("uint{bits} word carries high bits")));
        }
        Ok(word)
    }

    /// ABI uint32.
    pub fn abi_u32(&mut self) -> Result<u32> {
        let w = self.abi_uint(32)?;
        Ok(u32::from_be_bytes([w[28], w[29], w[30], w[31]]))
    }

    /// ABI uint64.
    pub fn abi_u64(&mut self) -> Result<u64> {
        let w = self.abi_uint(64)?;
        let mut b = [0u8; 8];
        b.copy_from_slice(&w[24..]);
        Ok(u64::from_be_bytes(b))
    }

    /// ABI uint256 that must fit in u128.
    pub fn abi_u256_as_u128(&mut self) -> Result<u128> {
        let w = self.abi_uint(128)?;
        let mut b = [0u8; 16];
        b.copy_from_slice(&w[16..]);
        Ok(u128::from_be_bytes(b))
    }

    /// ABI address (12 zero bytes, then 20).
    pub fn abi_address(&mut self) -> Result<[u8; 20]> {
        let w = self.abi_uint(160)?;
        let mut a = [0u8; 20];
        a.copy_from_slice(&w[12..]);
        Ok(a)
    }

    /// ABI offset word, relative to the enclosing tuple's start.
    pub fn abi_offset(&mut self) -> Result<usize> {
        let w = self.abi_uint(32)?;
        Ok(u32::from_be_bytes([w[28], w[29], w[30], w[31]]) as usize)
    }

    /// Require the dynamic field whose offset was `offset` (relative to a
    /// tuple starting at `base`) to begin exactly here: the one canonical
    /// layout puts every tail right after the previous one.
    pub fn abi_expect_tail(&self, base: usize, offset: usize) -> Result<()> {
        if base.checked_add(offset) != Some(self.pos) {
            return Err(malformed(format!(
                "non-canonical ABI offset {offset} (tail expected at {})",
                self.pos - base
            )));
        }
        Ok(())
    }

    /// ABI `bytes` tail of at most `max` bytes, with zero padding.
    pub fn abi_bytes(&mut self, max: usize) -> Result<Vec<u8>> {
        let len = self.abi_offset()?;
        if len > max {
            return Err(malformed(format!("bytes field of {len} exceeds {max}")));
        }
        let data = self.take(len)?.to_vec();
        let pad = (32 - len % 32) % 32;
        if self.take(pad)?.iter().any(|b| *b != 0) {
            return Err(malformed("non-zero ABI padding"));
        }
        Ok(data)
    }
}

/// Builder for the encodings [`Reader`] accepts.
#[derive(Default)]
pub struct Writer {
    out: Vec<u8>,
}

impl Writer {
    /// An empty writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// The bytes written.
    pub fn into_bytes(self) -> Vec<u8> {
        self.out
    }

    /// Current length.
    pub fn len(&self) -> usize {
        self.out.len()
    }

    /// Whether nothing has been written.
    pub fn is_empty(&self) -> bool {
        self.out.is_empty()
    }

    /// Raw bytes.
    pub fn raw(&mut self, b: &[u8]) -> &mut Self {
        self.out.extend_from_slice(b);
        self
    }

    /// One byte.
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.raw(&[v])
    }

    /// Little-endian u32.
    pub fn u32_le(&mut self, v: u32) -> &mut Self {
        self.raw(&v.to_le_bytes())
    }

    /// Big-endian u16.
    pub fn u16_be(&mut self, v: u16) -> &mut Self {
        self.raw(&v.to_be_bytes())
    }

    /// Big-endian u32.
    pub fn u32_be(&mut self, v: u32) -> &mut Self {
        self.raw(&v.to_be_bytes())
    }

    /// Little-endian u128.
    pub fn u128_le(&mut self, v: u128) -> &mut Self {
        self.raw(&v.to_le_bytes())
    }

    /// A BCS length (ULEB128).
    pub fn uleb128(&mut self, mut v: usize) -> &mut Self {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                return self.u8(b);
            }
            self.u8(b | 0x80);
        }
    }

    /// A BCS byte vector.
    pub fn bcs_bytes(&mut self, b: &[u8]) -> &mut Self {
        self.uleb128(b.len()).raw(b)
    }

    /// Little-endian u64.
    pub fn u64_le(&mut self, v: u64) -> &mut Self {
        self.raw(&v.to_le_bytes())
    }

    /// Big-endian u64.
    pub fn u64_be(&mut self, v: u64) -> &mut Self {
        self.raw(&v.to_be_bytes())
    }

    /// Big-endian u128.
    pub fn u128_be(&mut self, v: u128) -> &mut Self {
        self.raw(&v.to_be_bytes())
    }

    /// 256-bit little-endian amount.
    pub fn u256_le(&mut self, v: u128) -> &mut Self {
        self.raw(&v.to_le_bytes()).raw(&[0u8; 16])
    }

    /// Borsh byte vector.
    pub fn borsh_bytes(&mut self, b: &[u8]) -> &mut Self {
        self.u32_le(b.len() as u32).raw(b)
    }

    /// u32 big-endian length-prefixed bytes.
    pub fn be_bytes(&mut self, b: &[u8]) -> &mut Self {
        self.raw(&(b.len() as u32).to_be_bytes()).raw(b)
    }

    /// u16 big-endian length-prefixed string.
    pub fn be_str(&mut self, s: &str) -> &mut Self {
        self.raw(&(s.len() as u16).to_be_bytes()).raw(s.as_bytes())
    }

    /// ABI word holding an unsigned integer.
    pub fn abi_uint(&mut self, v: u128) -> &mut Self {
        self.raw(&[0u8; 16]).raw(&v.to_be_bytes())
    }

    /// ABI address word.
    pub fn abi_address(&mut self, a: &[u8; 20]) -> &mut Self {
        self.raw(&[0u8; 12]).raw(a)
    }

    /// ABI `bytes` tail: length word, data, zero padding.
    pub fn abi_bytes(&mut self, b: &[u8]) -> &mut Self {
        self.abi_uint(b.len() as u128).raw(b);
        let pad = (32 - b.len() % 32) % 32;
        self.raw(&vec![0u8; pad])
    }
}

/// Size of an ABI `bytes` tail holding `len` bytes.
pub fn abi_bytes_size(len: usize) -> usize {
    32 + len.div_ceil(32) * 32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailing_bytes_are_refused() {
        let mut r = Reader::new(&[1, 2, 3]);
        r.take(2).unwrap();
        assert!(r.finish().is_err());
    }

    #[test]
    fn truncation_is_an_error_not_a_short_read() {
        let mut r = Reader::new(&[0u8; 31]);
        assert!(r.word().is_err());
    }

    #[test]
    fn abi_words_with_high_bits_are_refused() {
        let mut w = [0u8; 32];
        w[0] = 1;
        assert!(Reader::new(&w).abi_u64().is_err());
        assert!(Reader::new(&w).abi_address().is_err());
        assert!(Reader::new(&w).abi_u256_as_u128().is_err());
    }

    #[test]
    fn abi_bytes_padding_must_be_zero() {
        let mut w = Writer::new();
        w.abi_bytes(&[7, 7, 7]);
        let mut bytes = w.into_bytes();
        assert_eq!(Reader::new(&bytes).abi_bytes(64).unwrap(), vec![7, 7, 7]);
        *bytes.last_mut().unwrap() = 1;
        assert!(Reader::new(&bytes).abi_bytes(64).is_err());
    }
}
