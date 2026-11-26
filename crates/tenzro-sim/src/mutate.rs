//! Small changes to a validator's own messages: what
//! [`Behaviour::Mutate`](crate::config::Behaviour::Mutate) sends.
//!
//! Each change touches one field of one message the validator's core made:
//! a round, an epoch, a checkpoint index or a sequence off by one, another
//! author or signer, a digest or a root with a bit changed, a list cut short
//! or with an entry repeated. The message stays well formed, so it reaches
//! the receiving core rather than being dropped by a decoder.

use tenzro_consensus::{Message, ValidatorIndex};

/// The `n`th draw of validator `id` in a run seeded with `seed`.
pub(crate) fn draw(seed: u64, id: u32, n: u64) -> u64 {
    let mut z = seed ^ (u64::from(id) << 32) ^ n.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// `m` with one field changed, chosen by `draw`, in a committee of `size`.
pub(crate) fn mutate(m: &Message, draw: u64, size: ValidatorIndex) -> Message {
    // Another member of the committee than `i`.
    let other = |i: ValidatorIndex| {
        let n = u64::from(size.max(2));
        ((u64::from(i) + 1 + (draw >> 8) % (n - 1)) % n) as ValidatorIndex
    };
    let pick = draw % 5;
    let mut out = m.clone();
    match &mut out {
        Message::Propose(v) => match pick {
            0 => v.round += 1,
            1 => v.round = v.round.saturating_sub(1),
            2 => v.epoch = v.epoch.saturating_sub(1),
            3 => v.source = other(v.source),
            _ => {
                v.strong.pop();
            }
        },
        Message::Signals(signals) => {
            if let Some(s) = signals.first_mut() {
                match pick {
                    0 => s.round += 1,
                    1 => s.round = s.round.saturating_sub(1),
                    2 => s.source = other(s.source),
                    3 => s.digest[0] ^= 1,
                    _ => {
                        let again = *s;
                        signals.push(again);
                    }
                }
            }
        }
        Message::Batch(b) => match pick {
            0 => b.sequence += 1,
            1 => b.epoch = b.epoch.saturating_sub(1),
            2 => b.author = other(b.author),
            3 => {
                b.body.pop();
            }
            _ => b.transactions = b.transactions.wrapping_add(1),
        },
        Message::Vote(v) => match pick {
            0 => v.checkpoint.index += 1,
            1 => v.checkpoint.index = v.checkpoint.index.saturating_sub(1),
            2 => v.checkpoint.epoch = v.checkpoint.epoch.saturating_sub(1),
            3 => v.signer = other(v.signer),
            _ => v.checkpoint.state_root[0] ^= 1,
        },
        Message::Certificate(c) => match pick {
            0 => {
                c.signers.pop();
                c.sessions.pop();
                c.signatures.pop();
            }
            1 => {
                c.signatures.pop();
            }
            2 => c.checkpoint.index += 1,
            3 => c.checkpoint.blocks_root[0] ^= 1,
            _ => {
                if let Some(first) = c.signers.first().copied() {
                    c.signers.push(first);
                }
            }
        },
        Message::Vertices(vertices) => {
            if let Some(v) = vertices.first_mut() {
                match pick {
                    0 => v.round += 1,
                    1 => v.source = other(v.source),
                    2 => v.epoch = v.epoch.saturating_sub(1),
                    _ => {
                        v.strong.pop();
                    }
                }
            }
        }
        Message::Batches(batches) => {
            if let Some(b) = batches.first_mut() {
                match pick {
                    0 => b.sequence += 1,
                    1 => b.author = other(b.author),
                    _ => {
                        b.body.pop();
                    }
                }
            }
        }
        Message::FetchVertices(digests) | Message::FetchBatches(digests) => {
            if let Some(d) = digests.first_mut() {
                d[0] ^= 1;
            }
        }
        Message::FetchOrdering(index) => *index = index.wrapping_add(1),
        Message::Frontier(f) => match pick {
            0 | 1 => f.next_checkpoint += 1,
            _ => f.round = f.round.map(|r| r + 1),
        },
        Message::Ordering(_) => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draws_follow_from_the_seed_the_validator_and_the_count() {
        assert_eq!(draw(7, 3, 11), draw(7, 3, 11));
        let draws = [
            draw(7, 3, 11),
            draw(8, 3, 11),
            draw(7, 4, 11),
            draw(7, 3, 12),
        ];
        for (i, a) in draws.iter().enumerate() {
            for b in &draws[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn a_request_goes_out_changed_and_names_another_member() {
        for d in 0..64u64 {
            assert_ne!(
                mutate(&Message::FetchOrdering(7), d, 4),
                Message::FetchOrdering(7)
            );
            let fetch = Message::FetchVertices(vec![[5; 32], [6; 32]]);
            match mutate(&fetch, d, 4) {
                Message::FetchVertices(digests) => {
                    assert_ne!(digests[0], [5; 32]);
                    assert_eq!(digests[1], [6; 32]);
                }
                other => panic!("unexpected {other:?}"),
            }
        }
    }
}
