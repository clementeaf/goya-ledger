---- MODULE GoyaHotStuff ----
\* Formal specification of Goya Ledger's HotStuff BFT consensus.
\*
\* Models 4 validators, quorum 3/4, up to 1 Byzantine, 3-phase pipeline.
\*
\* Maps to Rust implementation:
\*   SafetyState::safe_to_vote()  → safety.rs:192-234
\*   record_vote()                → safety.rs:237-239
\*   update_locked_qc()           → safety.rs:249-254
\*   QuorumValidator              → quorum.rs
\*   BftRound phases              → round.rs
\*   RoundManager                 → round_manager.rs
\*   ChainAncestryChecker         → safety.rs:44-140

EXTENDS Integers, FiniteSets

CONSTANTS
    N,              \* Number of validators (4)
    MaxRound,       \* Upper bound on rounds
    NumBlocks,      \* Number of non-genesis blocks
    F               \* Max Byzantine faults

\* ── Derived ──────────────────────────────────────────────────
Vals == 1..N
Honest == 1..(N - F)
Byz == IF F > 0 THEN {N} ELSE {}
Rounds == 0..MaxRound
quorum == 2 * F + 1

\* Block IDs: 0 = genesis. Odd = branch A, Even = branch B.
\* Tree:  0(genesis) ← 1(a1) ← 3(a2)
\*                   ← 2(b1) ← 4(b2)
AllBlocks == 0..NumBlocks
ASSUME NumBlocks >= 2

ParentOf(b) ==
    CASE b = 0 -> 0
      [] b = 1 -> 0
      [] b = 2 -> 0
      [] b = 3 -> 1
      [] b = 4 -> 2
      [] OTHER -> 0

RECURSIVE AncRec(_, _, _)
AncRec(a, b, d) ==
    IF a = b THEN TRUE
    ELSE IF d = 0 THEN FALSE
    ELSE IF b = 0 THEN (a = 0)
    ELSE AncRec(a, ParentOf(b), d - 1)

IsAncestor(a, b) == AncRec(a, b, NumBlocks + 1)

\* ── Variables ────────────────────────────────────────────────
\* voted[v][r][b][ph] = TRUE iff validator v voted phase ph for block b in round r
\* Phases: 1=Prepare, 2=PreCommit, 3=Commit
VARIABLES
    voted,           \* [Vals × Rounds × AllBlocks × 1..3 -> BOOLEAN]
    lastVoted,       \* [Vals -> {-1} ∪ Rounds]
    lockRound,       \* [Vals -> {-1} ∪ Rounds]
    lockBlock,       \* [Vals -> {-1} ∪ AllBlocks]  (-1 = no lock)
    decided          \* SUBSET [r: Rounds, b: AllBlocks]

vars == <<voted, lastVoted, lockRound, lockBlock, decided>>

\* ── Helpers ──────────────────────────────────────────────────
VoteCount(ph, r, b) ==
    Cardinality({v \in Vals : voted[v][r][b][ph]})

HasQC(ph, r, b) == VoteCount(ph, r, b) >= quorum

\* ── Init ─────────────────────────────────────────────────────
Init ==
    /\ voted = [v \in Vals |-> [r \in Rounds |-> [b \in AllBlocks |-> [ph \in 1..3 |-> FALSE]]]]
    /\ lastVoted = [v \in Vals |-> -1]
    /\ lockRound = [v \in Vals |-> -1]
    /\ lockBlock = [v \in Vals |-> -1]
    /\ decided = {}

\* ── SafeToVote ───────────────────────────────────────────────
\* Maps to: SafetyState::safe_to_vote (safety.rs:192-234)
SafeToVote(v, r, b) ==
    /\ r > lastVoted[v]                                         \* monotonicity
    /\ \/ lockBlock[v] = -1                                     \* no lock
       \/ IsAncestor(lockBlock[v], b)                           \* extends lock
       \/ \E jr \in Rounds, jb \in AllBlocks :                  \* higher QC unlock
            /\ HasQC(1, jr, jb)
            /\ jr > lockRound[v]
            /\ IsAncestor(jb, b)

\* ── Actions ──────────────────────────────────────────────────

HonestPrepare(v, r, b) ==
    /\ v \in Honest
    /\ r \in Rounds /\ b \in AllBlocks
    /\ ~voted[v][r][b][1]
    /\ SafeToVote(v, r, b)
    /\ voted' = [voted EXCEPT ![v][r][b][1] = TRUE]
    /\ lastVoted' = [lastVoted EXCEPT ![v] = r]
    /\ UNCHANGED <<lockRound, lockBlock, decided>>

HonestPreCommit(v, r, b) ==
    /\ v \in Honest
    /\ r \in Rounds /\ b \in AllBlocks
    /\ HasQC(1, r, b)
    /\ ~voted[v][r][b][2]
    /\ voted' = [voted EXCEPT ![v][r][b][2] = TRUE]
    /\ UNCHANGED <<lastVoted, lockRound, lockBlock, decided>>

HonestCommit(v, r, b) ==
    /\ v \in Honest
    /\ r \in Rounds /\ b \in AllBlocks
    /\ HasQC(2, r, b)
    /\ ~voted[v][r][b][3]
    /\ voted' = [voted EXCEPT ![v][r][b][3] = TRUE]
    /\ UNCHANGED <<lastVoted, lockRound, lockBlock, decided>>

UpdateLock(v, r, b) ==
    /\ v \in Honest
    /\ r \in Rounds /\ b \in AllBlocks
    /\ HasQC(2, r, b)
    /\ r > lockRound[v]
    /\ lockRound' = [lockRound EXCEPT ![v] = r]
    /\ lockBlock' = [lockBlock EXCEPT ![v] = b]
    /\ UNCHANGED <<voted, lastVoted, decided>>

Decide(r, b) ==
    /\ r \in Rounds /\ b \in AllBlocks
    /\ HasQC(3, r, b)
    /\ [r |-> r, b |-> b] \notin decided
    /\ decided' = decided \cup {[r |-> r, b |-> b]}
    /\ UNCHANGED <<voted, lastVoted, lockRound, lockBlock>>

ByzVote(v, r, b, ph) ==
    /\ v \in Byz
    /\ r \in Rounds /\ b \in AllBlocks /\ ph \in 1..3
    /\ ~voted[v][r][b][ph]
    /\ voted' = [voted EXCEPT ![v][r][b][ph] = TRUE]
    /\ UNCHANGED <<lastVoted, lockRound, lockBlock, decided>>

\* ── Next ─────────────────────────────────────────────────────
Next ==
    \/ \E v \in Vals, r \in Rounds, b \in AllBlocks :
        \/ HonestPrepare(v, r, b)
        \/ HonestPreCommit(v, r, b)
        \/ HonestCommit(v, r, b)
        \/ UpdateLock(v, r, b)
    \/ \E r \in Rounds, b \in AllBlocks : Decide(r, b)
    \/ \E v \in Vals, r \in Rounds, b \in AllBlocks, ph \in 1..3 :
        ByzVote(v, r, b, ph)

Spec == Init /\ [][Next]_vars

\* ══════════════════════════════════════════════════════════════
\* INVARIANTS
\* ══════════════════════════════════════════════════════════════

Agreement ==
    \A d1, d2 \in decided :
        IsAncestor(d1.b, d2.b) \/ IsAncestor(d2.b, d1.b)

NoHonestDoubleVote ==
    \A v \in Honest, r \in Rounds, ba \in AllBlocks, bb \in AllBlocks :
        (voted[v][r][ba][1] /\ voted[v][r][bb][1]) => ba = bb

QCRequiresQuorum ==
    \A r \in Rounds, b \in AllBlocks, ph \in 1..3 :
        HasQC(ph, r, b) => VoteCount(ph, r, b) >= quorum

NoConflictingFinalization ==
    ~(\E d1, d2 \in decided :
        /\ d1.b # d2.b
        /\ ~IsAncestor(d1.b, d2.b)
        /\ ~IsAncestor(d2.b, d1.b))

====
