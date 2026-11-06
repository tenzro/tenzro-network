//! SPL Token Program view of the one token ledger on the SVM.
//!
//! The SVM executor serves [`SPL_TOKEN_PROGRAM_ID`] natively: an owner's SPL
//! token account for a mint is the owner's own ledger account. Under the
//! wTNZO mint it holds native TNZO, with amounts converted between SPL's 9
//! decimals and native TNZO's 18 by truncation; under any other mint, which
//! is a token id, it holds that token in its own base units. `Transfer`
//! moves wTNZO, `TransferChecked` moves any mint, and `GetBalance` reads.
//! Supply cannot be changed through this program: `MintTo` and `Burn` are
//! refused, because supply moves only through the token's own ledger.
//!
//! The Token-2022 program id is a second view of the same ledger. It serves
//! `TransferChecked` through the one rule engine and reports a mint's
//! extensions as data derived from the token record: Pausable is the halt,
//! DefaultAccountState follows the `RequireClaim` rule, PermanentDelegate
//! is the force power held by the issuer alone, and ScaledUiAmount is
//! display only. Transfer hooks, confidential transfers and supply changes
//! outside `TokenOp` are refused by name ([`Token2022Refusal`]).

/// The wTNZO SPL mint address (32 bytes)
pub const WTNZO_SPL_MINT: [u8; 32] = {
    let mut bytes = [0u8; 32];
    bytes[0] = 0x57; // 'W'
    bytes[1] = 0x54; // 'T'
    bytes[2] = 0x4E; // 'N'
    bytes[3] = 0x5A; // 'Z'
    bytes[4] = 0x4F; // 'O'
    bytes
};

/// SPL Token Program ID served natively by the SVM executor
pub const SPL_TOKEN_PROGRAM_ID: [u8; 32] = {
    let mut bytes = [0u8; 32];
    bytes[0] = 0x06;
    bytes[1] = 0xdd;
    bytes[2] = 0xf6;
    bytes
};

/// Token-2022 program id (`TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`),
/// served as a second view of the same ledger: no store of its own.
pub const TOKEN_2022_PROGRAM_ID: [u8; 32] = [
    0x06, 0xdd, 0xf6, 0xe1, 0xee, 0x75, 0x8f, 0xde, 0x18, 0x42, 0x5d, 0xbc, 0xe4, 0x6c, 0xcd, 0xda,
    0xb6, 0x1a, 0xfc, 0x4d, 0x83, 0xb9, 0x0d, 0x27, 0xfe, 0xbd, 0xf9, 0x28, 0xd8, 0xa1, 0x8b, 0xfc,
];

/// Tenzro extension instruction on the Token-2022 view: read a mint's
/// extensions as Token-2022 TLV. Accounts: `[mint]`.
pub const GET_MINT_EXTENSIONS: u8 = 201;

/// Why the Token-2022 view refuses an instruction. Each has a stable name
/// the receipt carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Token2022Refusal {
    /// Transfer hooks run code on transfer; here transfer rules are token
    /// policy data, checked by the ledger's one rule engine.
    TransferHookUnsupported,
    /// Confidential balances are not part of the ledger.
    ConfidentialTransferUnsupported,
    /// Supply moves only through a `TokenOp` transaction.
    SupplyOutsideTokenOp,
    /// Token-2022 mints move only by `TransferChecked`.
    UncheckedTransfer,
    /// An extension instruction the ledger view does not carry.
    UnsupportedExtension(u8),
}

impl std::fmt::Display for Token2022Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Token2022Refusal::TransferHookUnsupported => {
                write!(
                    f,
                    "TransferHookUnsupported: transfer rules are token policy data, not hook programs"
                )
            }
            Token2022Refusal::ConfidentialTransferUnsupported => {
                write!(
                    f,
                    "ConfidentialTransferUnsupported: confidential balances are not part of the ledger"
                )
            }
            Token2022Refusal::SupplyOutsideTokenOp => {
                write!(
                    f,
                    "SupplyOutsideTokenOp: mint and burn go through the Token transaction"
                )
            }
            Token2022Refusal::UncheckedTransfer => {
                write!(
                    f,
                    "UncheckedTransfer: Token-2022 mints move by TransferChecked"
                )
            }
            Token2022Refusal::UnsupportedExtension(op) => {
                write!(
                    f,
                    "UnsupportedExtension: instruction {op} is not part of the ledger view"
                )
            }
        }
    }
}

/// The refusal for Token-2022 instruction `opcode`, or `None` when the view
/// serves it.
pub fn token_2022_refusal(opcode: u8) -> Option<Token2022Refusal> {
    match opcode {
        12 | 200 | GET_MINT_EXTENSIONS | 0 | 1 | 9 => None,
        36 => Some(Token2022Refusal::TransferHookUnsupported),
        27 | 37 | 42 => Some(Token2022Refusal::ConfidentialTransferUnsupported),
        7 | 8 | 14 | 15 => Some(Token2022Refusal::SupplyOutsideTokenOp),
        3 => Some(Token2022Refusal::UncheckedTransfer),
        other => Some(Token2022Refusal::UnsupportedExtension(other)),
    }
}

/// A mint extension as the Token-2022 view reports it, derived from the
/// token's ledger record.
#[derive(Debug, Clone, PartialEq)]
pub enum MintExtension {
    /// New accounts start frozen when holding needs a claim (the eligibility
    /// rule `RequireClaim`), initialized otherwise.
    DefaultAccountState {
        /// Whether new accounts start frozen.
        frozen: bool,
    },
    /// The account the force power belongs to, when the issuer holds it
    /// alone.
    PermanentDelegate {
        /// The delegate account.
        delegate: [u8; 32],
    },
    /// The halt switch.
    Pausable {
        /// The account holding the halt power, or zero.
        authority: [u8; 32],
        /// Whether holder transfers are halted.
        paused: bool,
    },
    /// Display scaling. Display only: balances never scale.
    ScaledUiAmount {
        /// The display multiplier.
        multiplier: f64,
    },
}

const EXT_DEFAULT_ACCOUNT_STATE: u16 = 6;
const EXT_PERMANENT_DELEGATE: u16 = 12;
const EXT_SCALED_UI_AMOUNT: u16 = 25;
const EXT_PAUSABLE: u16 = 26;

/// Encode `extensions` as Token-2022 TLV: a little-endian u16 type, a
/// little-endian u16 length, then the value.
pub fn encode_tlv(extensions: &[MintExtension]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in extensions {
        let (kind, value): (u16, Vec<u8>) = match e {
            MintExtension::DefaultAccountState { frozen } => {
                (EXT_DEFAULT_ACCOUNT_STATE, vec![if *frozen { 2 } else { 1 }])
            }
            MintExtension::PermanentDelegate { delegate } => {
                (EXT_PERMANENT_DELEGATE, delegate.to_vec())
            }
            MintExtension::Pausable { authority, paused } => {
                let mut v = authority.to_vec();
                v.push(u8::from(*paused));
                (EXT_PAUSABLE, v)
            }
            MintExtension::ScaledUiAmount { multiplier } => {
                let mut v = vec![0u8; 32];
                v.extend_from_slice(&multiplier.to_le_bytes());
                v.extend_from_slice(&0i64.to_le_bytes());
                v.extend_from_slice(&multiplier.to_le_bytes());
                (EXT_SCALED_UI_AMOUNT, v)
            }
        };
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&(value.len() as u16).to_le_bytes());
        out.extend_from_slice(&value);
    }
    out
}

/// Decode Token-2022 TLV written by [`encode_tlv`].
pub fn decode_tlv(mut bytes: &[u8]) -> Result<Vec<MintExtension>, String> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err("truncated TLV header".into());
        }
        let kind = u16::from_le_bytes([bytes[0], bytes[1]]);
        let len = usize::from(u16::from_le_bytes([bytes[2], bytes[3]]));
        let value = bytes.get(4..4 + len).ok_or("truncated TLV value")?;
        let arr32 = |v: &[u8]| <[u8; 32]>::try_from(&v[..32]).map_err(|_| "bad key".to_string());
        out.push(match (kind, len) {
            (EXT_DEFAULT_ACCOUNT_STATE, 1) => MintExtension::DefaultAccountState {
                frozen: value[0] == 2,
            },
            (EXT_PERMANENT_DELEGATE, 32) => MintExtension::PermanentDelegate {
                delegate: arr32(value)?,
            },
            (EXT_PAUSABLE, 33) => MintExtension::Pausable {
                authority: arr32(value)?,
                paused: value[32] != 0,
            },
            (EXT_SCALED_UI_AMOUNT, 56) => MintExtension::ScaledUiAmount {
                multiplier: f64::from_le_bytes(
                    value[32..40].try_into().map_err(|_| "bad multiplier")?,
                ),
            },
            (k, l) => {
                return Err(format!(
                    "extension type {k} with length {l} is not part of the view"
                ));
            }
        });
        bytes = &bytes[4 + len..];
    }
    Ok(out)
}

/// The Token-2022 extensions of token `id`, from its ledger record, or
/// `None` when no such token exists.
pub fn mint_extensions(
    state: &dyn crate::traits::VmState,
    id: &[u8; 32],
) -> Option<Vec<MintExtension>> {
    use tenzro_types::token_policy::{Authority, Power, Rule};
    let record = crate::token_ledger::read_token(state, id)?;
    let issuer = {
        let mut a = [0u8; 32];
        let c = &record.creator;
        a[..c.len().min(32)].copy_from_slice(&c[..c.len().min(32)]);
        a
    };
    let sole = |p: Power| record.powers.get(p) == Authority::Issuer;
    let mut out = vec![MintExtension::DefaultAccountState {
        frozen: record
            .policy
            .eligibility
            .iter()
            .any(|r| matches!(r, Rule::RequireClaim { .. })),
    }];
    if sole(Power::Force) {
        out.push(MintExtension::PermanentDelegate { delegate: issuer });
    }
    out.push(MintExtension::Pausable {
        authority: if sole(Power::Halt) { issuer } else { [0u8; 32] },
        paused: crate::token_ledger::halted(state, id),
    });
    out.push(MintExtension::ScaledUiAmount { multiplier: 1.0 });
    Some(out)
}

/// SPL instruction discriminators
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplInstruction {
    /// Initialize a new mint
    InitializeMint = 0,
    /// Initialize a new token account
    InitializeAccount = 1,
    /// Transfer tokens between accounts
    Transfer = 3,
    /// Approve delegate
    Approve = 4,
    /// Revoke delegate
    Revoke = 5,
    /// Mint tokens to an account
    MintTo = 7,
    /// Burn tokens from an account
    Burn = 8,
    /// Close an account
    CloseAccount = 9,
    /// Transfer tokens of a named mint, checking its decimals
    TransferChecked = 12,
    /// Get balance (Tenzro extension)
    GetBalance = 200,
    /// Read a mint's extensions as TLV (Tenzro extension, Token-2022 view)
    GetMintExtensions = 201,
}

impl SplInstruction {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(SplInstruction::InitializeMint),
            1 => Some(SplInstruction::InitializeAccount),
            3 => Some(SplInstruction::Transfer),
            4 => Some(SplInstruction::Approve),
            5 => Some(SplInstruction::Revoke),
            7 => Some(SplInstruction::MintTo),
            8 => Some(SplInstruction::Burn),
            9 => Some(SplInstruction::CloseAccount),
            12 => Some(SplInstruction::TransferChecked),
            200 => Some(SplInstruction::GetBalance),
            201 => Some(SplInstruction::GetMintExtensions),
            _ => None,
        }
    }
}
