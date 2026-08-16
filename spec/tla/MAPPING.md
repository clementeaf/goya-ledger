# TLA+ Spec → Rust Implementation Mapping

## State Variables

| TLA+ Variable | Rust Location | Notes |
|---|---|---|
| `voted[v][r][b][ph]` | `VoteCollector::votes` (`vote_collector.rs:31`) | TLA+ uses per-(v,r,b,ph) boolean; Rust uses `HashMap<String, VoteMessage>` per collector |
| `lastVoted[v]` | `SafetyState::last_voted_round` (`safety.rs:158`) | Both: highest round where Prepare vote was cast |
| `lockRound[v]` | `SafetyState::locked_qc.round` (`safety.rs:156`) | TLA+ splits round/block; Rust uses `Option<QuorumCertificate>` |
| `lockBlock[v]` | `SafetyState::locked_qc.block_hash` (`safety.rs:156`) | Same |
| `decided` | `RoundManager::highest_commit_qc` (`round_manager.rs:62`) | TLA+ tracks set; Rust tracks latest only |

## Actions

| TLA+ Action | Rust Function | File:Line |
|---|---|---|
| `SafeToVote(v, r, b)` | `SafetyState::safe_to_vote()` | `safety.rs:192-234` |
| `HonestPrepare(v, r, b)` | `RoundManager::process_event(Proposal{..})` | `round_manager.rs:183-218` |
| `HonestPreCommit(v, r, b)` | `BftRound::advance_phase(Prepare, ..)` | `round.rs:253-260` |
| `HonestCommit(v, r, b)` | `BftRound::advance_phase(PreCommit, ..)` | `round.rs:262-267` |
| `UpdateLock(v, r, b)` | `SafetyState::update_locked_qc()` | `safety.rs:249-254` |
| `Decide(r, b)` | `BftRound::advance_phase(Commit, ..)` | `round.rs:271-278` |
| `ByzVote(v, r, b, ph)` | N/A (adversary model) | Byzantine behavior verified via `validate_received_qc` (`round_manager.rs:251-276`) |
| `HasQC(ph, r, b)` | `QuorumValidator::validate_qc()` | `quorum.rs:106-129` |
| `IsAncestor(a, b)` | `ChainAncestryChecker::is_ancestor()` | `safety.rs:99-139` |

## Safety Rules (safe_to_vote)

| TLA+ Rule | Rust Code | Description |
|---|---|---|
| `r > lastVoted[v]` | `safety.rs:200-207` | Vote monotonicity — prevents equivocation |
| `lockBlock[v] = -1` | `safety.rs:210-213` | No lock → accept any proposal |
| `IsAncestor(lockBlock[v], b)` | `safety.rs:216-218` | Rule 2b: proposal extends locked block |
| `∃ jr, jb: HasQC(1,jr,jb) ∧ jr > lockRound[v] ∧ IsAncestor(jb,b)` | `safety.rs:223-228` | Rule 2c: higher QC + ancestry → safe unlock |

## Invariants

| TLA+ Invariant | Rust Test Coverage | Description |
|---|---|---|
| `Agreement` | `bft_e2e::two_finalized_blocks_never_conflict`, `bft_mldsa65_e2e::*` | Primary safety: no conflicting finalization |
| `NoHonestDoubleVote` | `safety::vote_monotonicity_prevents_equivocation` | Monotonicity prevents double-vote |
| `QCRequiresQuorum` | `quorum::validate_qc_*`, `vote_collector::third_vote_reaches_quorum` | Quorum threshold enforced |
| `NoConflictingFinalization` | `vote_collector::quorum_intersection_all_pairs` | Quorum intersection prevents conflicting QCs |

## Divergences

1. **Leader rotation**: TLA+ allows any validator to propose in any round (overapproximation). Rust enforces round-robin (`round_manager.rs:113-118`). The overapproximation is safe for safety checking.

2. **QC signature verification**: TLA+ models QC existence via vote counts. Rust additionally verifies cryptographic signatures (`validate_received_qc` in `round_manager.rs:251-276`). The TLA+ model assumes honest validators' votes can't be forged (Byzantine can only contribute their own votes).

3. **Network model**: TLA+ is fully asynchronous (any enabled action can fire). Rust has explicit timeouts and round advancement. The TLA+ model is more general, making safety results stronger.

4. **Phase voting**: TLA+ allows an honest validator to vote PreCommit/Commit for any (r,b) once the QC exists, regardless of whether it voted Prepare. Rust couples phases within a single BftRound instance. The TLA+ model is more permissive, which is conservative for safety.

5. **Block tree**: TLA+ uses a hardcoded tree via `ParentOf`. Rust uses `ChainAncestryChecker` backed by `BlockStore`. Both compute the same ancestry relation.

## Model Parameters

| Config | N | F | MaxRound | Blocks | Purpose |
|---|---|---|---|---|---|
| `GoyaHotStuff.cfg` | 4 | 1 | 1 | {0,1,2} | Exhaustive (tractable) |
| `GoyaHotStuff_full.cfg` | 4 | 1 | 3 | {0,1,2,3,4} | Simulation (1M random traces) |
