//! ERC-20 selectors, event topics and ABI helpers shared by the wTNZO pointer
//! (`0x1001`), the token factory (`0x1002`) and the NFT factory (`0x1006`).
//!
//! Every decoder here uses checked arithmetic: offsets and lengths come from
//! calldata, so an addition that wraps would let a crafted offset slip past a
//! bounds check.

/// ERC-20 function selectors
pub mod selectors {
    /// name() -> string
    pub const NAME: [u8; 4] = [0x06, 0xfd, 0xde, 0x03];
    /// symbol() -> string
    pub const SYMBOL: [u8; 4] = [0x95, 0xd8, 0x9b, 0x41];
    /// decimals() -> uint8
    pub const DECIMALS: [u8; 4] = [0x31, 0x3c, 0xe5, 0x67];
    /// totalSupply() -> uint256
    pub const TOTAL_SUPPLY: [u8; 4] = [0x18, 0x16, 0x0d, 0xdd];
    /// balanceOf(address) -> uint256
    pub const BALANCE_OF: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];
    /// transfer(address,uint256) -> bool
    pub const TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
    /// approve(address,uint256) -> bool
    pub const APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];
    /// allowance(address,address) -> uint256
    pub const ALLOWANCE: [u8; 4] = [0xdd, 0x62, 0xed, 0x3e];
    /// transferFrom(address,address,uint256) -> bool
    pub const TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];
}

/// ERC-20 event topic hashes
pub mod events {
    use sha3::{Digest, Keccak256};

    fn topic(sig: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&Keccak256::digest(sig));
        out
    }

    /// Transfer(address indexed from, address indexed to, uint256 value)
    pub fn transfer_topic() -> [u8; 32] {
        topic(b"Transfer(address,address,uint256)")
    }

    /// Approval(address indexed owner, address indexed spender, uint256 value)
    pub fn approval_topic() -> [u8; 32] {
        topic(b"Approval(address,address,uint256)")
    }
}

/// ABI encoding and bounds-checked decoding.
pub mod abi {
    /// Encode a uint256 (left-padded to 32 bytes)
    pub fn encode_uint256(value: u128) -> Vec<u8> {
        let mut bytes = vec![0u8; 32];
        bytes[16..32].copy_from_slice(&value.to_be_bytes());
        bytes
    }

    /// Encode a bool as uint256
    pub fn encode_bool(value: bool) -> Vec<u8> {
        let mut bytes = vec![0u8; 32];
        bytes[31] = value as u8;
        bytes
    }

    /// Encode an address (left-padded to 32 bytes)
    pub fn encode_address(addr: &[u8; 20]) -> Vec<u8> {
        let mut bytes = vec![0u8; 32];
        bytes[12..].copy_from_slice(addr);
        bytes
    }

    /// Encode a string as a single dynamic return value (offset, length,
    /// padded data).
    pub fn encode_string(s: &str) -> Vec<u8> {
        let bytes = s.as_bytes();
        let padded_len = bytes.len().div_ceil(32) * 32;
        let mut result = Vec::with_capacity(64 + padded_len);
        result.extend_from_slice(&encode_uint256(32));
        result.extend_from_slice(&encode_uint256(bytes.len() as u128));
        result.extend_from_slice(bytes);
        result.resize(64 + padded_len, 0);
        result
    }

    /// Encode a uint8 (left-padded to 32 bytes)
    pub fn encode_uint8(value: u8) -> Vec<u8> {
        let mut bytes = vec![0u8; 32];
        bytes[31] = value;
        bytes
    }

    /// The 32-byte word at `offset`, if it lies within `input`.
    pub fn word_at(input: &[u8], offset: usize) -> Option<&[u8]> {
        let end = offset.checked_add(32)?;
        input.get(offset..end)
    }

    /// A uint256 at `offset` that fits in u128. `None` if out of bounds or
    /// the value exceeds u128.
    pub fn decode_uint256_at(input: &[u8], offset: usize) -> Option<u128> {
        let w = word_at(input, offset)?;
        if w[..16].iter().any(|b| *b != 0) {
            return None;
        }
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&w[16..]);
        Some(u128::from_be_bytes(bytes))
    }

    /// A uint256 at `offset` used as a length or offset into calldata.
    pub fn decode_usize_at(input: &[u8], offset: usize) -> Option<usize> {
        usize::try_from(decode_uint256_at(input, offset)?).ok()
    }

    /// An address at `offset`; the 12 padding bytes must be zero.
    pub fn decode_address_at(input: &[u8], offset: usize) -> Option<[u8; 20]> {
        let w = word_at(input, offset)?;
        if w[..12].iter().any(|b| *b != 0) {
            return None;
        }
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&w[12..]);
        Some(addr)
    }

    /// A bytes32 at `offset`.
    pub fn decode_bytes32_at(input: &[u8], offset: usize) -> Option<[u8; 32]> {
        let w = word_at(input, offset)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(w);
        Some(out)
    }

    /// Dynamic `bytes` whose head word (holding its offset) is at `head`.
    /// Offsets are relative to `base`, the start of the enclosing tuple.
    pub fn decode_dynamic_bytes(input: &[u8], base: usize, head: usize) -> Option<&[u8]> {
        let rel = decode_usize_at(input, head)?;
        let start = base.checked_add(rel)?;
        let len = decode_usize_at(input, start)?;
        let data_start = start.checked_add(32)?;
        let data_end = data_start.checked_add(len)?;
        input.get(data_start..data_end)
    }

    /// Dynamic `string` whose head word is at `head`, relative to `base`.
    pub fn decode_dynamic_string(input: &[u8], base: usize, head: usize) -> Option<String> {
        String::from_utf8(decode_dynamic_bytes(input, base, head)?.to_vec()).ok()
    }

    /// Dynamic `uint256[]` whose head word is at `head`, relative to `base`.
    pub fn decode_uint256_array(input: &[u8], base: usize, head: usize) -> Option<Vec<u128>> {
        let rel = decode_usize_at(input, head)?;
        let start = base.checked_add(rel)?;
        let len = decode_usize_at(input, start)?;
        let mut out = Vec::new();
        for i in 0..len {
            let off = start.checked_add(32)?.checked_add(i.checked_mul(32)?)?;
            out.push(decode_uint256_at(input, off)?);
        }
        Some(out)
    }

    /// Dynamic `string[]` whose head word is at `head`, relative to `base`.
    ///
    /// Element offsets are caller data and may all point at the same bytes;
    /// the decoded strings together may not exceed the input's length, so a
    /// call cannot make the decoder copy more than it sent.
    pub fn decode_string_array(input: &[u8], base: usize, head: usize) -> Option<Vec<String>> {
        let rel = decode_usize_at(input, head)?;
        let start = base.checked_add(rel)?;
        let len = decode_usize_at(input, start)?;
        let elems = start.checked_add(32)?;
        let mut out = Vec::new();
        let mut total = 0usize;
        for i in 0..len {
            let s = decode_dynamic_bytes(input, elems, elems.checked_add(i.checked_mul(32)?)?)?;
            total = total.checked_add(s.len())?;
            if total > input.len() {
                return None;
            }
            out.push(String::from_utf8(s.to_vec()).ok()?);
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::abi::*;

    #[test]
    fn offsets_near_usize_max_are_rejected_not_wrapped() {
        // head word says the string starts at 2^64 - 16: adding 32 wraps in
        // unchecked arithmetic.
        let mut input = vec![0u8; 64];
        input[24..32].copy_from_slice(&(u64::MAX - 15).to_be_bytes());
        assert_eq!(decode_dynamic_string(&input, 0, 0), None);
        assert_eq!(decode_uint256_array(&input, 0, 0), None);
        assert_eq!(decode_string_array(&input, 0, 0), None);
    }

    #[test]
    fn string_array_elements_cannot_alias_one_string_into_many_copies() {
        // 128 KiB of call data: 2,048 heads, every one pointing at the same
        // 64 KiB string. Decoding it as written copies 128 MiB.
        let n = 2_048usize;
        let s = 64 * 1024;
        let mut input = Vec::new();
        input.extend_from_slice(&[0u8; 31]);
        input.push(32);
        let mut len = [0u8; 32];
        len[24..].copy_from_slice(&(n as u64).to_be_bytes());
        input.extend_from_slice(&len);
        let mut at = [0u8; 32];
        at[24..].copy_from_slice(&((32 * n) as u64).to_be_bytes());
        for _ in 0..n {
            input.extend_from_slice(&at);
        }
        let mut slen = [0u8; 32];
        slen[24..].copy_from_slice(&(s as u64).to_be_bytes());
        input.extend_from_slice(&slen);
        input.resize(input.len() + s, b'a');
        assert!(input.len() <= 131_072 + 128);
        assert_eq!(decode_string_array(&input, 0, 0), None);

        // Distinct strings still decode.
        let mut ok = Vec::new();
        ok.extend_from_slice(&word_usize(32));
        ok.extend_from_slice(&word_usize(2));
        ok.extend_from_slice(&word_usize(64));
        ok.extend_from_slice(&word_usize(128));
        ok.extend_from_slice(&encode_string("ab")[32..]);
        ok.extend_from_slice(&encode_string("cd")[32..]);
        assert_eq!(
            decode_string_array(&ok, 0, 0),
            Some(vec!["ab".to_string(), "cd".to_string()])
        );
    }

    fn word_usize(v: usize) -> Vec<u8> {
        let mut w = vec![0u8; 32];
        w[24..].copy_from_slice(&(v as u64).to_be_bytes());
        w
    }

    #[test]
    fn dynamic_string_round_trip() {
        let enc = encode_string("tenzro");
        assert_eq!(decode_dynamic_string(&enc, 0, 0).as_deref(), Some("tenzro"));
    }

    #[test]
    fn address_with_dirty_padding_is_rejected() {
        let mut w = vec![0u8; 32];
        w[0] = 1;
        assert_eq!(decode_address_at(&w, 0), None);
    }
}
