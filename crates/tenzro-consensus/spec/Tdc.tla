-------------------------------- MODULE Tdc --------------------------------
(***************************************************************************)
(* The ordering, checkpoint and epoch layers of Tenzro consensus.           *)
(*                                                                         *)
(* Reliable broadcast is modeled by the guarantees it gives: each          *)
(* (epoch, round, author) delivers at most one vertex, the same one        *)
(* everywhere, and honest authors' vertices are the ones they proposed. A  *)
(* Byzantine author may send different first proposals to different       *)
(* validators, but only one of them can be delivered. Validators learn     *)
(* delivered vertices in any order (asynchrony), always causally closed.   *)
(*                                                                         *)
(* An epoch orders until its handover: HaltAfter commits. A validator      *)
(* enters the next epoch once a quorum has certified the handover          *)
(* checkpoint, whose body is the epoch's committed sequence.               *)
(*                                                                         *)
(* Batches. Every vertex introduces its author's batch of that round,     *)
(* <<author, round>>. The round's leader also carries other authors'       *)
(* batches of its round, which honest validators echo only once they hold  *)
(* them, so a delivered vertex carries only batches that exist. When a     *)
(* leader vertex is the committed anchor its carried batches are ordered   *)
(* with it; every batch is ordered once, at its first ordering.            *)
(*                                                                         *)
(* Checked invariants:                                                     *)
(*   Agreement      two honest validators never commit different leaders   *)
(*                  at the same position of one epoch's commit sequence;   *)
(*   Certificates   no two different checkpoint bodies for one (epoch,     *)
(*                  index) are signed by a quorum;                         *)
(*   Handover       no validator commits past an epoch's halt, and every   *)
(*                  honest validator that entered the next epoch did so    *)
(*                  on the same certified prefix;                          *)
(*   BatchAgreement two honest validators order the same batches at the    *)
(*                  same position, and no batch at two positions.          *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, Sequences, TLC

CONSTANTS
    V,          \* validators (the same committee in both epochs)
    Byz,        \* Byzantine validators, |Byz| <= f
    MaxRound,   \* last round explored per epoch
    LeaderSeq,  \* leaders, cycled over the rounds
    HaltAfter,  \* commits per epoch before the handover halt
    Epochs,     \* number of epochs explored
    None        \* a model value: no vertex delivered or proposed

N == Cardinality(V)
F == (N - 1) \div 3
Q == N - F
Honest == V \ Byz
Rounds == 0..MaxRound
EpochIds == 1..Epochs
\* The schedule differs by epoch, as it is seeded from the handover.
Leader(e, r) == LeaderSeq[((r + e - 1) % Len(LeaderSeq)) + 1]

ASSUME Cardinality(Byz) <= F

Vertex(a, r, parents, nv, carry) == [author |-> a, round |-> r, parents |-> parents, nv |-> nv, carry |-> carry]

\* What the round-r leader a carries: the other authors' batches of round r.
Carry(a, r) == {<<b, r>> : b \in V \ {a}}

VARIABLES
    dlv,        \* dlv[e][r][a]: the delivered vertex of (e, r, a), or None
    prop,       \* prop[i][e][r][a]: the first proposal i saw from a in (e, r), or None
    know,       \* know[i][e]: set of <<r, a>> validator i holds in epoch e
    committed,  \* committed[i][e]: sequence of committed leader rounds
    votes,      \* votes[i]: set of <<e, index, body>> checkpoint votes i signed
    epoch       \* epoch[i]: the epoch validator i is in

vars == <<dlv, prop, know, committed, votes, epoch>>

Init ==
    /\ dlv = [e \in EpochIds |-> [r \in Rounds |-> [a \in V |-> None]]]
    /\ prop = [i \in V |-> [e \in EpochIds |-> [r \in Rounds |-> [a \in V |-> None]]]]
    /\ know = [i \in V |-> [e \in EpochIds |-> {}]]
    /\ committed = [i \in V |-> [e \in EpochIds |-> <<>>]]
    /\ votes = [i \in V |-> {}]
    /\ epoch = [i \in V |-> 1]

Delivered(e, r) == {a \in V : dlv[e][r][a] # None}

StrongRefs(e, r, a) == IF dlv[e][r][a] = None THEN {} ELSE dlv[e][r][a].parents

\* Byzantine validators have no epoch of their own; they act in any epoch
\* some honest validator has reached.
Live(e) == \E i \in Honest : epoch[i] >= e

(***************************************************************************)
(* Proposal and delivery.                                                   *)
(***************************************************************************)

HonestPropose(a, r) ==
    /\ a \in Honest
    /\ LET e == epoch[a] IN
       /\ dlv[e][r][a] = None
       /\ Len(committed[a][e]) < HaltAfter
       /\ \/ /\ r = 0
             /\ LET v == Vertex(a, 0, {}, {}, IF a = Leader(e, 0) THEN Carry(a, 0) ELSE {})
                IN /\ dlv' = [dlv EXCEPT ![e][0][a] = v]
                   /\ prop' = [i \in V |-> [prop[i] EXCEPT ![e][0][a] = v]]
          \/ /\ r > 0
             /\ LET held == {b \in V : <<r-1, b>> \in know[a][e]}
                    lead == Leader(e, r-1)
                    nvs  == {b \in V \ {a} : <<r, b>> \in know[a][e] /\ lead \notin StrongRefs(e, r, b)}
                IN /\ Cardinality(held) >= Q
                   /\ \/ a # Leader(e, r) \/ lead \in held \/ Cardinality(nvs) + 1 >= Q
                   /\ LET v == Vertex(a, r, held, IF a = Leader(e, r) /\ lead \notin held THEN nvs ELSE {},
                                     IF a = Leader(e, r) THEN Carry(a, r) ELSE {})
                      IN /\ dlv' = [dlv EXCEPT ![e][r][a] = v]
                         /\ prop' = [i \in V |-> [prop[i] EXCEPT ![e][r][a] = v]]
    /\ UNCHANGED <<know, committed, votes, epoch>>

ByzFirstProposal(a, e, r, i, parents) ==
    /\ a \in Byz
    /\ Live(e)
    /\ r > 0
    /\ prop[i][e][r][a] = None
    /\ parents \subseteq Delivered(e, r-1)
    /\ Cardinality(parents) >= Q
    /\ prop' = [prop EXCEPT ![i][e][r][a] = Vertex(a, r, parents, {}, {})]
    /\ UNCHANGED <<dlv, know, committed, votes, epoch>>

\* A Byzantine author carries whatever it likes of the batches that exist,
\* whether or not it leads the round: nothing, or every other author's
\* batch of the round.
ByzDeliver(a, e, r, parents, carry) ==
    /\ a \in Byz
    /\ Live(e)
    /\ dlv[e][r][a] = None
    /\ \/ r = 0 /\ parents = {}
       \/ r > 0 /\ parents \subseteq Delivered(e, r-1) /\ Cardinality(parents) >= Q
    /\ carry \in {{}, Carry(a, r)}
    /\ dlv' = [dlv EXCEPT ![e][r][a] = Vertex(a, r, parents, {}, carry)]
    /\ UNCHANGED <<prop, know, committed, votes, epoch>>

Learn(i, r, a) ==
    /\ i \in Honest
    /\ LET e == epoch[i] IN
       /\ dlv[e][r][a] # None
       /\ <<r, a>> \notin know[i][e]
       /\ \A b \in dlv[e][r][a].parents : <<r-1, b>> \in know[i][e]
       /\ \A b \in dlv[e][r][a].nv : <<r, b>> \in know[i][e]
       /\ know' = [know EXCEPT ![i][e] = @ \union {<<r, a>>}]
    /\ UNCHANGED <<dlv, prop, committed, votes, epoch>>

(***************************************************************************)
(* Commit rule.                                                             *)
(***************************************************************************)

RECURSIVE Reach(_, _, _, _, _, _)
Reach(i, e, r1, a1, r0, a0) ==
    IF r1 = r0 THEN a1 = a0
    ELSE IF r1 < r0 \/ <<r1, a1>> \notin know[i][e] THEN FALSE
    ELSE \E b \in dlv[e][r1][a1].parents : Reach(i, e, r1 - 1, b, r0, a0)

ValidLeader(i, e, r) ==
    LET l == Leader(e, r) IN
    /\ <<r, l>> \in know[i][e]
    /\ \/ r = 0
       \/ Leader(e, r-1) \in dlv[e][r][l].parents
       \/ Cardinality({b \in dlv[e][r][l].nv : <<r, b>> \in know[i][e]
                          /\ Leader(e, r-1) \notin dlv[e][r][b].parents}) + 1 >= Q

DirectVotes(i, e, r) ==
    {a \in V : /\ r + 1 <= MaxRound
               /\ prop[i][e][r+1][a] # None
               /\ Leader(e, r) \in prop[i][e][r+1][a].parents}

DirectCommit(i, e, r) == ValidLeader(i, e, r) /\ Cardinality(DirectVotes(i, e, r)) >= Q

LastRound(i, e) == IF committed[i][e] = <<>> THEN -1 ELSE committed[i][e][Len(committed[i][e])]

RECURSIVE Earliest(_, _, _, _)
Earliest(i, e, r, lo) ==
    LET cands == {x \in lo..(r-1) : ValidLeader(i, e, x) /\ Reach(i, e, r, Leader(e, r), x, Leader(e, x))}
    IN IF cands = {} THEN r ELSE Earliest(i, e, CHOOSE x \in cands : \A y \in cands : y <= x, lo)

Commit(i, r) ==
    /\ i \in Honest
    /\ LET e == epoch[i] IN
       /\ Len(committed[i][e]) < HaltAfter
       /\ r > LastRound(i, e)
       /\ DirectCommit(i, e, r)
       /\ LET x == Earliest(i, e, r, LastRound(i, e) + 1)
          IN committed' = [committed EXCEPT ![i][e] = Append(@, x)]
    /\ UNCHANGED <<dlv, prop, know, votes, epoch>>

(***************************************************************************)
(* Checkpoints and handover. One checkpoint per committed leader; its body *)
(* is the epoch's committed prefix.                                        *)
(***************************************************************************)

HonestVote(i) ==
    /\ i \in Honest
    /\ LET e == epoch[i] IN
       \E k \in 1..Len(committed[i][e]) :
          /\ <<e, k, SubSeq(committed[i][e], 1, k)>> \notin votes[i]
          /\ votes' = [votes EXCEPT ![i] = @ \union {<<e, k, SubSeq(committed[i][e], 1, k)>>}]
    /\ UNCHANGED <<dlv, prop, know, committed, epoch>>

ByzVote(i, e, k, body) ==
    /\ i \in Byz
    /\ votes' = [votes EXCEPT ![i] = @ \union {<<e, k, body>>}]
    /\ UNCHANGED <<dlv, prop, know, committed, epoch>>

Signers(e, k, body) == {i \in V : <<e, k, body>> \in votes[i]}

\* An honest validator whose epoch has halted enters the next once the
\* handover checkpoint it signed is certified.
Enter(i) ==
    /\ i \in Honest
    /\ epoch[i] < Epochs
    /\ LET e == epoch[i] IN
       /\ Len(committed[i][e]) = HaltAfter
       /\ Cardinality(Signers(e, HaltAfter, committed[i][e])) >= Q
    /\ epoch' = [epoch EXCEPT ![i] = @ + 1]
    /\ UNCHANGED <<dlv, prop, know, committed, votes>>

Next ==
    \/ \E a \in V, r \in Rounds : HonestPropose(a, r)
    \/ \E a \in Byz, e \in EpochIds, r \in Rounds, i \in Honest, P \in SUBSET V : ByzFirstProposal(a, e, r, i, P)
    \/ \E a \in Byz, e \in EpochIds, r \in Rounds, P \in SUBSET V :
         \E C \in {{}, Carry(a, r)} : ByzDeliver(a, e, r, P, C)
    \/ \E i \in V, r \in Rounds, a \in V : Learn(i, r, a)
    \/ \E i \in V, r \in Rounds : Commit(i, r)
    \/ \E i \in V : HonestVote(i)
    \/ \E i \in V : Enter(i)
    \/ \E i \in Byz, e \in EpochIds, k \in 1..HaltAfter :
         \E j \in Honest : \E m \in 1..Len(committed[j][e]) : ByzVote(i, e, k, SubSeq(committed[j][e], 1, m))

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Invariants.                                                              *)
(***************************************************************************)

Agreement ==
    \A i, j \in Honest : \A e \in EpochIds :
        \A k \in 1..Len(committed[i][e]) :
            k <= Len(committed[j][e]) => committed[i][e][k] = committed[j][e][k]

CertificateUniqueness ==
    \A i, j \in V : \A x \in votes[i], y \in votes[j] :
        (x[1] = y[1] /\ x[2] = y[2] /\ x[3] # y[3]) =>
            ~(Cardinality(Signers(x[1], x[2], x[3])) >= Q /\ Cardinality(Signers(y[1], y[2], y[3])) >= Q)

\* The vertices a delivered vertex reaches by strong references, itself
\* included.
RECURSIVE History(_, _, _)
History(e, r, a) ==
    {<<r, a>>} \union
        IF r = 0 THEN {} ELSE UNION {History(e, r - 1, b) : b \in dlv[e][r][a].parents}

\* The batches introduced by, or carried by the anchor of, the k-th commit
\* of validator i, before removing those ordered earlier.
Offered(i, e, k) ==
    LET x == committed[i][e][k]
        l == Leader(e, x)
    IN {<<y[2], y[1]>> : y \in History(e, x, l)} \union dlv[e][x][l].carry

\* The batches the k-th commit of validator i orders.
RECURSIVE OrderedBefore(_, _, _)
OrderedBefore(i, e, k) ==
    IF k = 1 THEN {} ELSE OrderedBefore(i, e, k - 1) \union Offered(i, e, k - 1)

Segment(i, e, k) == Offered(i, e, k) \ OrderedBefore(i, e, k)

BatchAgreement ==
    \A i, j \in Honest : \A e \in EpochIds :
        \A k \in 1..Len(committed[i][e]) :
            /\ k <= Len(committed[j][e]) => Segment(i, e, k) = Segment(j, e, k)
            /\ \A m \in 1..Len(committed[j][e]) :
                 m # k => Segment(i, e, k) \cap Segment(j, e, m) = {}

Handover ==
    /\ \A i \in Honest : \A e \in EpochIds : Len(committed[i][e]) <= HaltAfter
    /\ \A i, j \in Honest : \A e \in EpochIds :
         (epoch[i] > e /\ epoch[j] > e) => committed[i][e] = committed[j][e]

=============================================================================
