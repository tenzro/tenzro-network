//! ERC-7579 execution calldata for smart accounts.
//!
//! A UserOperation's `call_data` is the account's
//! `execute(bytes32 mode, bytes executionCalldata)` call. The mode's first
//! byte is the call type:
//!
//! - `0x00` single: `executionCalldata = target (20) || value (32) || callData`
//! - `0x01` batch: `executionCalldata = abi.encode(Execution[])`, where
//!   `Execution = (address target, uint256 value, bytes callData)`
//!
//! The second byte is the exec type. Only the default exec type (`0x00`,
//! revert on failure) is accepted, so a batch is all-or-nothing. Every other
//! mode byte must be zero.
//!
//! This one codec is used by the EntryPoint to execute and by every
//! validator module to read what an operation will do, so validation always
//! sees exactly the calls that run. Decoding is canonical: input that does
//! not re-encode to the same bytes is refused, so no two encodings of the
//! same calls exist.

use serde::{Deserialize, Serialize};

/// `bytes4(keccak256("execute(bytes32,bytes)"))`.
pub const EXECUTE_SELECTOR: [u8; 4] = [0xe9, 0xae, 0x5c, 0x53];

/// Call type: one call.
pub const CALLTYPE_SINGLE: u8 = 0x00;

/// Call type: several calls, executed in order.
pub const CALLTYPE_BATCH: u8 = 0x01;

/// Exec type: revert the whole operation when any call fails.
pub const EXECTYPE_DEFAULT: u8 = 0x00;

/// Most calls one operation may carry.
pub const MAX_BATCH_CALLS: usize = 64;

/// One call an account makes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Execution {
    /// Contract or account being called.
    pub target: [u8; 20],
    /// Native value sent with the call (smallest unit).
    pub value: u128,
    /// Calldata passed to the target.
    pub call_data: Vec<u8>,
}

impl Execution {
    /// First four bytes of the calldata, or `None` for a plain value transfer.
    pub fn selector(&self) -> Option<[u8; 4]> {
        if self.call_data.len() >= 4 {
            let mut s = [0u8; 4];
            s.copy_from_slice(&self.call_data[..4]);
            Some(s)
        } else {
            None
        }
    }
}

/// Why calldata is not a valid `execute` call.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExecutionDecodeError {
    #[error("call_data is not an execute(bytes32,bytes) call")]
    NotExecute,
    #[error("unsupported execution mode: call type {call_type:#04x}, exec type {exec_type:#04x}")]
    UnsupportedMode { call_type: u8, exec_type: u8 },
    #[error("malformed execution calldata: {0}")]
    Malformed(&'static str),
    #[error("batch is empty")]
    EmptyBatch,
    #[error("batch has {0} calls, more than the limit of {MAX_BATCH_CALLS}")]
    TooManyCalls(usize),
    #[error("value does not fit in 128 bits")]
    ValueTooLarge,
    #[error("execution calldata is not canonically encoded")]
    NonCanonical,
}

/// Total native value the calls send.
pub fn total_value(executions: &[Execution]) -> u128 {
    executions
        .iter()
        .fold(0u128, |acc, e| acc.saturating_add(e.value))
}

fn word_u64(n: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&n.to_be_bytes());
    w
}

fn word_u128(n: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&n.to_be_bytes());
    w
}

fn word_address(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

fn padded_len(n: usize) -> usize {
    n.div_ceil(32) * 32
}

fn push_bytes(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&word_u64(data.len() as u64));
    out.extend_from_slice(data);
    out.resize(out.len() + (padded_len(data.len()) - data.len()), 0);
}

fn wrap(call_type: u8, execution_calldata: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 96 + padded_len(execution_calldata.len()));
    out.extend_from_slice(&EXECUTE_SELECTOR);
    let mut mode = [0u8; 32];
    mode[0] = call_type;
    mode[1] = EXECTYPE_DEFAULT;
    out.extend_from_slice(&mode);
    out.extend_from_slice(&word_u64(0x40));
    push_bytes(&mut out, execution_calldata);
    out
}

/// Encode one call as `execute(single mode, target || value || callData)`.
pub fn encode_single(execution: &Execution) -> Vec<u8> {
    let mut inner = Vec::with_capacity(52 + execution.call_data.len());
    inner.extend_from_slice(&execution.target);
    inner.extend_from_slice(&word_u128(execution.value));
    inner.extend_from_slice(&execution.call_data);
    wrap(CALLTYPE_SINGLE, &inner)
}

/// Encode several calls as `execute(batch mode, abi.encode(Execution[]))`.
pub fn encode_batch(executions: &[Execution]) -> Vec<u8> {
    let mut tuples: Vec<Vec<u8>> = Vec::with_capacity(executions.len());
    for e in executions {
        let mut t = Vec::with_capacity(96 + 32 + padded_len(e.call_data.len()));
        t.extend_from_slice(&word_address(&e.target));
        t.extend_from_slice(&word_u128(e.value));
        t.extend_from_slice(&word_u64(0x60));
        push_bytes(&mut t, &e.call_data);
        tuples.push(t);
    }
    let mut inner = Vec::new();
    inner.extend_from_slice(&word_u64(0x20));
    inner.extend_from_slice(&word_u64(executions.len() as u64));
    let mut offset = 32 * executions.len();
    for t in &tuples {
        inner.extend_from_slice(&word_u64(offset as u64));
        offset += t.len();
    }
    for t in &tuples {
        inner.extend_from_slice(t);
    }
    wrap(CALLTYPE_BATCH, &inner)
}

/// `base + by`, refusing a sum past `usize::MAX` (offsets are caller data).
fn offset(base: usize, by: usize) -> Result<usize, ExecutionDecodeError> {
    base.checked_add(by)
        .ok_or(ExecutionDecodeError::Malformed("offset overflow"))
}

fn read_word(data: &[u8], at: usize) -> Result<&[u8], ExecutionDecodeError> {
    data.get(
        at..at
            .checked_add(32)
            .ok_or(ExecutionDecodeError::Malformed("offset overflow"))?,
    )
    .ok_or(ExecutionDecodeError::Malformed("truncated word"))
}

fn read_usize(data: &[u8], at: usize) -> Result<usize, ExecutionDecodeError> {
    let w = read_word(data, at)?;
    if w[..24].iter().any(|b| *b != 0) {
        return Err(ExecutionDecodeError::Malformed(
            "length or offset too large",
        ));
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&w[24..]);
    usize::try_from(u64::from_be_bytes(b))
        .map_err(|_| ExecutionDecodeError::Malformed("length or offset too large"))
}

fn read_u128(bytes: &[u8]) -> Result<u128, ExecutionDecodeError> {
    if bytes[..16].iter().any(|b| *b != 0) {
        return Err(ExecutionDecodeError::ValueTooLarge);
    }
    let mut b = [0u8; 16];
    b.copy_from_slice(&bytes[16..32]);
    Ok(u128::from_be_bytes(b))
}

fn read_bytes(data: &[u8], at: usize) -> Result<Vec<u8>, ExecutionDecodeError> {
    let len = read_usize(data, at)?;
    let start = at + 32;
    let end = start
        .checked_add(len)
        .ok_or(ExecutionDecodeError::Malformed("length overflow"))?;
    data.get(start..end)
        .map(|s| s.to_vec())
        .ok_or(ExecutionDecodeError::Malformed("truncated bytes"))
}

fn decode_batch(inner: &[u8]) -> Result<Vec<Execution>, ExecutionDecodeError> {
    let array_at = read_usize(inner, 0)?;
    let n = read_usize(inner, array_at)?;
    if n == 0 {
        return Err(ExecutionDecodeError::EmptyBatch);
    }
    if n > MAX_BATCH_CALLS {
        return Err(ExecutionDecodeError::TooManyCalls(n));
    }
    let heads = offset(array_at, 32)?;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let tuple_at = offset(heads, read_usize(inner, offset(heads, 32 * i)?)?)?;
        let target_word = read_word(inner, tuple_at)?;
        if target_word[..12].iter().any(|b| *b != 0) {
            return Err(ExecutionDecodeError::Malformed("address has high bits set"));
        }
        let mut target = [0u8; 20];
        target.copy_from_slice(&target_word[12..]);
        let value = read_u128(read_word(inner, offset(tuple_at, 32)?)?)?;
        let data_at = offset(tuple_at, read_usize(inner, offset(tuple_at, 64)?)?)?;
        let call_data = read_bytes(inner, data_at)?;
        out.push(Execution {
            target,
            value,
            call_data,
        });
    }
    Ok(out)
}

/// Decode a UserOperation's `call_data` into the calls it makes, in order.
///
/// Refuses anything that is not a canonically encoded `execute` call in the
/// single or batch call type with the default exec type.
pub fn decode_execute(call_data: &[u8]) -> Result<Vec<Execution>, ExecutionDecodeError> {
    if call_data.len() < 4 || call_data[..4] != EXECUTE_SELECTOR {
        return Err(ExecutionDecodeError::NotExecute);
    }
    let body = &call_data[4..];
    let mode = read_word(body, 0)?;
    let (call_type, exec_type) = (mode[0], mode[1]);
    if exec_type != EXECTYPE_DEFAULT
        || (call_type != CALLTYPE_SINGLE && call_type != CALLTYPE_BATCH)
        || mode[2..].iter().any(|b| *b != 0)
    {
        return Err(ExecutionDecodeError::UnsupportedMode {
            call_type,
            exec_type,
        });
    }
    let inner_at = read_usize(body, 32)?;
    let inner = read_bytes(body, inner_at)?;

    let executions = if call_type == CALLTYPE_SINGLE {
        if inner.len() < 52 {
            return Err(ExecutionDecodeError::Malformed(
                "single execution shorter than 52 bytes",
            ));
        }
        let mut target = [0u8; 20];
        target.copy_from_slice(&inner[..20]);
        let value = read_u128(&inner[20..52])?;
        vec![Execution {
            target,
            value,
            call_data: inner[52..].to_vec(),
        }]
    } else {
        decode_batch(&inner)?
    };

    let canonical = if call_type == CALLTYPE_SINGLE {
        encode_single(&executions[0])
    } else {
        encode_batch(&executions)
    };
    if canonical != call_data {
        return Err(ExecutionDecodeError::NonCanonical);
    }
    Ok(executions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_offset_past_the_address_space_is_refused_not_wrapped() {
        let word = |v: u64| {
            let mut w = [0u8; 32];
            w[24..].copy_from_slice(&v.to_be_bytes());
            w
        };
        // Batch body: array at 32, one element, its tuple offset u64::MAX.
        let mut inner = Vec::new();
        inner.extend_from_slice(&word(32));
        inner.extend_from_slice(&word(1));
        inner.extend_from_slice(&word(u64::MAX));
        inner.extend_from_slice(&[0u8; 96]);
        let mut cd = EXECUTE_SELECTOR.to_vec();
        let mut mode = [0u8; 32];
        mode[0] = CALLTYPE_BATCH;
        cd.extend_from_slice(&mode);
        cd.extend_from_slice(&word(64));
        cd.extend_from_slice(&word(inner.len() as u64));
        cd.extend_from_slice(&inner);
        assert_eq!(
            decode_execute(&cd),
            Err(ExecutionDecodeError::Malformed("offset overflow"))
        );
    }

    fn exec(t: u8, value: u128, data: &[u8]) -> Execution {
        Execution {
            target: [t; 20],
            value,
            call_data: data.to_vec(),
        }
    }

    #[test]
    fn selector_is_the_erc7579_execute_selector() {
        let h = tenzro_crypto::hash::keccak256(b"execute(bytes32,bytes)");
        assert_eq!(&h.as_bytes()[..4], &EXECUTE_SELECTOR);
    }

    #[test]
    fn single_round_trips() {
        let e = exec(0x11, 5, &[0xa9, 0x05, 0x9c, 0xbb, 1, 2, 3]);
        let cd = encode_single(&e);
        assert_eq!(decode_execute(&cd).unwrap(), vec![e]);
    }

    #[test]
    fn batch_round_trips_in_order() {
        let calls = vec![
            exec(0x11, 1, b""),
            exec(0x22, 0, &[0xde, 0xad, 0xbe, 0xef, 9]),
            exec(0x33, 7, &[0u8; 70]),
        ];
        let cd = encode_batch(&calls);
        assert_eq!(decode_execute(&cd).unwrap(), calls);
        assert_eq!(total_value(&calls), 8);
    }

    #[test]
    fn try_mode_and_unknown_call_types_are_refused() {
        let mut cd = encode_batch(&[exec(1, 0, b"")]);
        cd[5] = 0x01; // exec type "try": a failing call would not revert the rest
        assert!(matches!(
            decode_execute(&cd),
            Err(ExecutionDecodeError::UnsupportedMode { .. })
        ));
        let mut cd = encode_single(&exec(1, 0, b""));
        cd[4] = 0xff; // delegatecall
        assert!(matches!(
            decode_execute(&cd),
            Err(ExecutionDecodeError::UnsupportedMode { .. })
        ));
    }

    #[test]
    fn non_execute_and_truncated_input_is_refused() {
        assert_eq!(
            decode_execute(&[0x42; 64]),
            Err(ExecutionDecodeError::NotExecute)
        );
        let cd = encode_batch(&[exec(1, 0, b"abcd"), exec(2, 0, b"")]);
        assert!(decode_execute(&cd[..cd.len() - 40]).is_err());
    }

    #[test]
    fn a_second_encoding_of_the_same_calls_is_refused() {
        // Trailing bytes after the encoded calls decode to the same calls,
        // but they are a different encoding and must not validate.
        let calls = vec![exec(1, 3, b"")];
        let mut cd = encode_batch(&calls);
        cd.extend_from_slice(&[0u8; 32]);
        assert_eq!(decode_execute(&cd), Err(ExecutionDecodeError::NonCanonical));
    }

    #[test]
    fn empty_and_oversized_batches_are_refused() {
        let cd = encode_batch(&[]);
        assert_eq!(decode_execute(&cd), Err(ExecutionDecodeError::EmptyBatch));
        let many: Vec<Execution> = (0..=MAX_BATCH_CALLS)
            .map(|i| exec(i as u8, 0, b""))
            .collect();
        assert_eq!(
            decode_execute(&encode_batch(&many)),
            Err(ExecutionDecodeError::TooManyCalls(MAX_BATCH_CALLS + 1))
        );
    }
}
