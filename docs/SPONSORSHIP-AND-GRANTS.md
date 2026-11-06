# Sponsorship and grants

The treasury pays two things out of the TNZO it already holds: sponsorship of
approved validators and providers, and grants to approved developers,
contributors and community members. Nothing is issued: the supply is fixed at
genesis and neither path creates TNZO. Running a node and building on the
network stay open to everyone; only these two payouts are gated.

Every disbursement is one governance proposal. There is no schedule, no
standing emission and no payout without a proposal, except the two
verified-work releases listed at the end, which carry their own caps.

## Approval

- `approve_operator` records a validator or provider with the criteria it was
  approved on. The chain checks the operator's machine identity holds a TPM
  endorsement a recognised root signs and counts its verified-available hours
  in the history named. The region and the independence declaration are
  stored as stated, with a link to the public statement.
- `approve_grantee` records a developer, contributor or community grantee
  with its criteria. The grantee must hold a registered identity.
- `revoke_operator` and `revoke_grantee` stop every later payment at once. A
  sponsored bond already held is recalled by its own proposal.

Approval confers no vote, no reward and no class. The same rules apply to
every recipient.

## What is paid

| Payout | Proposal | Paid only against |
|---|---|---|
| Sponsored validator bond | `sponsor_validator_bond` | an approved validator with a live bond |
| Operator running cost | `sponsor_operator_running_cost` | hours the challenge protocol judged the operator available; each hour backs one payment |
| Running cost from the reserve | `running_cost_payment` | the same: an approved operator, unused verified hours, the yearly caps and the proposal limit; the queue then pays within the reserve caps and the treasury period limit, and drops a payment whose operator was revoked |
| Running cost in a stable asset | `sponsor_operator_stable` | the same hours, valued in US dollars, in an approved USD stable asset the treasury holds |
| Treasury action on another chain | `treasury_remote_action` | an action that moves value names an approved operator, verified hours and the settlement asset that prices it; an action that moves nothing needs none |
| Grant | `treasury_grant`, `release_grant_tranche` | a named milestone per payment; the vote records the first as met; later tranches are released by their own proposal (the default) or against verified milestones (below) |

A grant names the grantee, one milestone for each payment and the amount.
Revoking the grantee stops the tranches still to be released.

Unowned funds are not a payout route. `recover_unowned_funds` draws only on
the staking vault's surplus over what it owes validators and returns it to the
treasury; the treasury is never a source and a person is never the
destination.

## Stable-asset payouts

Sponsorship and grants may be paid in an enabled, priced, on-peg USD entry of
the settlement-asset registry, so a falling TNZO price does not shrink what a
verified hour or a milestone is worth. A grant names the asset (`asset`); a
stable running cost uses `sponsor_operator_stable`. Amounts are in the asset's
smallest unit and are valued in US dollars at the validator rate. The gate is
unchanged: approved recipient, verified hours or a milestone, the yearly caps,
the outflow limit. The asset moves from the treasury's balance and nothing is
issued. A stable grant vests liquid, and every stable payout is a large spend
for the vote.

| Parameter | Meaning |
|---|---|
| `sponsorship.yearly_max_usd` | stable sponsorship in a 365-day period, whole dollars; one operator at most one third |
| `sponsorship.running_cost_per_verified_epoch_usd_e6` | most one verified hour backs, micro-dollars |
| `grants.per_grantee_yearly_max_usd` | one grantee in a 365-day period, whole dollars |
| `treasury.sponsorship_grants_yearly_max_usd` | sponsorship and grants together, whole dollars |
| `treasury.proposal_outflow_exception_bps` | headroom above the period limit one flagged stable sponsorship payment may use, basis points of the period's opening stable holdings (maximum 500) |

All are zero at genesis. The treasury outflow limit applies to the value of
the stable holdings with the same governed basis points as for TNZO (per
proposal and per 30-day period), kept separately. A stable sponsorship that
sets `period_exception` may exceed the period limit by the exception, never
the per-proposal limit or the yearly caps.

## Grant release

`release` on a grant is `governed` (the default) or `scheduled`. A governed
grant needs one `release_grant_tranche` proposal per tranche. A scheduled
grant carries its milestone schedule in the one approved proposal: it names
the verifiers (at most nine, never the grantee) and a threshold. A verifier
records a tranche's milestone with the `verify_milestone` funding operation;
once the threshold has recorded it anyone may send `release_milestone`, which
pays that tranche, in order and once. Each tranche re-checks the grantee's
approval, the yearly caps, the reserve floor and the outflow limit, so a
revoked grantee or a spent cap stops it. A release proposal for a scheduled
grant, and a milestone release for a governed one, are refused.

## Caps

All start at zero, so nothing flows until governance sets them.

| Parameter | Meaning |
|---|---|
| `sponsorship.yearly_max_tnzo` | sponsorship in a 365-day period; one operator receives at most one third of it |
| `sponsorship.running_cost_per_verified_epoch_wei` | most one verified-available hour backs |
| `grants.per_grantee_yearly_max_tnzo` | one grantee in a 365-day period |
| `treasury.sponsorship_grants_yearly_max_tnzo` | sponsorship and grants together in a 365-day period |

Every payout also counts against the treasury outflow caps: 2% of the balance
per proposal and 3% in any 30 days.

## Applying

A new operator cannot file the approval themselves: the proposal needs a
proposer holding 1% of the bonded stake. Three commands cover what an
operator can do:

```bash
tenzro sponsor check
tenzro sponsor apply
tenzro sponsor status
```

`check` reads the node and judges the account against the criteria the chain
enacts an approval on. The machine identity and account come from
`tenzro_getNodeStatus`; verified-available hours from `tenzro_slaVerdict` for
each hourly epoch in the window (`--hours`, 168 by default); the approval
record, the amount paid and the caps from `tenzro_getTreasuryPayouts`;
governance-sponsored stake from `tenzro_getSponsoredBond`; and an approval
proposal in flight from `tenzro_listProposals`. The node has no read for the
TPM endorsement chain, which the chain checks when the proposal is enacted, so
`check` states what the platform makes of it: a Secure Enclave has no TPM
endorsement certificate and a Jetson's firmware TPM has no recognised root, so
neither can be approved today.

`apply` runs the same check, writes the result to
`~/.tenzro/sponsor-application.json`, and prints two routes. The first is the
exact `tenzro governance propose-approve-operator` command, with the account,
machine identity and verified epochs filled in, for a proposer to run. The
second is `tenzro funding request-grant`, a treasury grant request the
operator files themselves; the treasury pays its gas, so an account with no
balance can file it.

`status` shows the approval record, what sponsorship has paid, the caps in
force and any stake the operator is waiting on. Tenzro Control shows the same
reads and criteria in the Sponsorship panel on its Dashboard.

All caps start at zero, so an approved operator is paid nothing until
governance sets them.

## Reading it

`tenzro_getTreasuryPayouts` (MCP `get_treasury_payouts`, CLI
`tenzro governance payouts`) lists every disbursement with its recipient,
amount, class (validator, provider, developer, contributor, community), the
proposal that paid it and the milestone or verified hours it was paid
against. It also returns the total per class and the governed caps, and with
an address its approvals and the total it has been paid. Each disbursement is
logged as `TreasuryPayout`.

## Unattended releases

Two payouts carry no proposal because they pay verified work as it happens:
the availability reward (a verified-available verdict, hardware-bound, off
until governance sets it) and the reconciliation duty reward. Both count
against the treasury outflow period and are forfeited, not forced, once its
cap is spent.
