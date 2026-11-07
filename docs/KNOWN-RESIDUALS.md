# Known residuals

## The participation roster at epoch close

The count of consecutive epochs a validator has missed is kept in chain state
and decides when an inactive validator is moved to exit. When an epoch closes,
the node takes the closing epoch's validator list from its own in-memory epoch
manager. A node that does not hold that epoch's set (restored from a snapshot
without epoch history, or its epoch store missing) skips the write that the
other nodes make, and its state root then differs from theirs.

This is a residual state-split risk, low on a freshly launched network where
every node has run from the first epoch. It must be redesigned before mainnet:
the roster has to come from committed chain state at the parent version of the
block, the change needs an activation height and a version gate so a rolling
upgrade does not split old and new nodes, and snapshot restore must rebuild the
validator registry from what the chain commits.

## The record age rule has no activation gate

A signed record and the batch root that signs it must be dated within a governed
age (`records.max_record_age_ms`) before the block that verifies them, and the
ML-DSA requirement is judged by the block's time rather than by the dates the
signer wrote. The launch genesis starts with these rules in force, so every node
runs the same binary and agrees. A later upgrade of a network that is already
running must not ship the age rule as it is: it has to take effect from a chain
height, so that blocks produced before the upgrade still verify the same way on
every node.

## Batched records on a genesis with a faster calendar

A node dates the records it signs by the wall clock. The chain judges them by the
calendar time of the block. On a genesis whose `calendar_scale` is above 1 those
two clocks differ, and training receipts and inference evidence signed in a batch
fall outside the age window and are refused. The launch genesis uses a scale of
1, where the two agree. A network started with a larger scale needs the record
dates taken from the same calendar as the blocks before it can use batched
records.

## The signing health flag is not a reliable alarm

When a node's identity key has no ML-DSA leg and the network starts to require
it, the node stops signing and sets a health flag. The flag clears itself about
half a second later, because the ticker clears it on any tick that finds nothing
pending, and a node that is started after the activation moment never sets it.
So the flag cannot be relied on to raise an alarm. Operators watch for
the refusal line the node logs at start-up and when signing is first refused.
Making the flag clear only after a signature the hardware really produced, and
set at start, is post-launch work, with its test.


## A restarted validator can stay outside the mesh for minutes under packet loss

A validator that restarts holds a new disclosure key and an empty endpoint book,
and learns each peer endpoint only from a copy sealed to that key. A peer seals
and publishes its set when the restarted validator announces, but that single
publication can reach the validator before its gossip mesh has formed and be
lost. The sealed set then rode only every tenth announcement (30 s apart), so
the validator logged "the peer has not disclosed its endpoint" and could not
dial for about five minutes. The set is now repeated on the next three
announcements after any change, and rides every fourth otherwise. What stays
open: a four-validator run also stopped finalizing for 246 s on three of four
validators when the fourth was stopped; its logs were not kept, so whether the
same loss explains it is not established. The next run that restarts a
validator under loss should record the sealed-set publications and receipts on
both sides. A member that lacks a peer's disclosure asking for the sealed copy,
instead of waiting for the sender's timer, is the remaining design change.
