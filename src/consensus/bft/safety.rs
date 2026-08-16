//! HotStuff safety rules — locking, vote monotonicity, ancestry checks.
//!
//! Invariant: **two finalized blocks are never conflicting** — for any pair
//! of committed blocks A and B, A is an ancestor of B or B of A.
//!
//! Lock lifecycle (mapped to our 3-phase + Decide flow):
//! - `high_qc`   updated on PrepareQC  (one-chain)
//! - `locked_qc`  updated on PreCommitQC (two-chain — THE LOCK)
//! - finalization on CommitQC → Decide   (three-chain)
//!
//! Locking at PreCommitQC (not PrepareQC) preserves liveness: a lone
//! PrepareQC without PreCommitQC means the quorum has not confirmed
//! awareness of the prepare, so locking there could stall the chain
//! after a single timeout.

#[cfg(test)]
use super::types::BftPhase;
use super::types::QuorumCertificate;

// ── Ancestry ────────────────────────────────────────────────────────────────

/// Returns true if `ancestor` is an ancestor of (or equal to) `descendant`
/// in the block chain.
pub trait AncestryChecker: Send + Sync {
    fn is_ancestor(&self, ancestor: &[u8; 32], descendant: &[u8; 32]) -> bool;
}

/// Permissive checker — always returns true.
/// Used when ancestry cannot be verified at the consensus layer
/// and the QC round comparison is the sole safety gate.
#[derive(Clone)]
pub struct AlwaysExtends;

impl AncestryChecker for AlwaysExtends {
    fn is_ancestor(&self, _ancestor: &[u8; 32], _descendant: &[u8; 32]) -> bool {
        true
    }
}

// ── Safety errors ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyError {
    RoundNotMonotonic {
        proposal: u64,
        last_voted: u64,
    },
    LockedConflict {
        justify_round: Option<u64>,
        lock_round: u64,
    },
}

impl std::fmt::Display for SafetyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RoundNotMonotonic {
                proposal,
                last_voted,
            } => write!(
                f,
                "round {proposal} <= last voted round {last_voted}"
            ),
            Self::LockedConflict {
                justify_round,
                lock_round,
            } => write!(
                f,
                "locked at round {lock_round}, justify_qc round {:?} does not supersede and proposal does not extend lock",
                justify_round
            ),
        }
    }
}

// ── Safety state ────────────────────────────────────────────────────────────

/// Per-validator safety state that persists across rounds.
#[derive(Default)]
pub struct SafetyState {
    /// Highest PrepareQC seen. Leaders include this as `justify_qc`.
    high_qc: Option<QuorumCertificate>,
    /// Highest PreCommitQC seen — the lock.
    locked_qc: Option<QuorumCertificate>,
    /// Highest round in which this validator cast a Prepare vote.
    last_voted_round: Option<u64>,
}

impl SafetyState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn high_qc(&self) -> Option<&QuorumCertificate> {
        self.high_qc.as_ref()
    }

    pub fn locked_qc(&self) -> Option<&QuorumCertificate> {
        self.locked_qc.as_ref()
    }

    pub fn last_voted_round(&self) -> Option<u64> {
        self.last_voted_round
    }

    /// Check whether it is safe to vote for a proposal in `proposal_round`.
    ///
    /// # Rules (HotStuff-derived)
    ///
    /// 1. **Monotonicity**: `proposal_round > last_voted_round`
    /// 2. **Lock check** — one of:
    ///    a. No lock exists (early rounds)
    ///    b. Proposal *extends* the locked block (ancestry verification)
    ///    c. `justify_qc.round > locked_qc.round` (safe unlock via higher QC)
    ///
    /// The ancestry check (2b) uses `is_ancestor(locked_block, proposed_block)`,
    /// NOT hash equality — a child or grandchild of the locked block is valid.
    pub fn safe_to_vote(
        &self,
        proposal_round: u64,
        proposal_block_hash: &[u8; 32],
        justify_qc: Option<&QuorumCertificate>,
        ancestry: &dyn AncestryChecker,
    ) -> Result<(), SafetyError> {
        // 1. Monotonicity — prevents equivocation across rounds.
        if let Some(last) = self.last_voted_round {
            if proposal_round <= last {
                return Err(SafetyError::RoundNotMonotonic {
                    proposal: proposal_round,
                    last_voted: last,
                });
            }
        }

        // 2. Lock check.
        let lock = match &self.locked_qc {
            None => return Ok(()),
            Some(qc) => qc,
        };

        // 2c. Liveness: justify_qc with strictly higher round supersedes lock.
        if let Some(jqc) = justify_qc {
            if jqc.round > lock.round {
                return Ok(());
            }
        }

        // 2b. Safety: proposal extends the locked block.
        if ancestry.is_ancestor(&lock.block_hash, proposal_block_hash) {
            return Ok(());
        }

        Err(SafetyError::LockedConflict {
            justify_round: justify_qc.map(|q| q.round),
            lock_round: lock.round,
        })
    }

    /// Record that we voted Prepare in `round`.
    pub fn record_vote(&mut self, round: u64) {
        self.last_voted_round = Some(self.last_voted_round.map_or(round, |prev| prev.max(round)));
    }

    /// Update `high_qc` on PrepareQC. Only updates if strictly higher round.
    pub fn update_high_qc(&mut self, qc: &QuorumCertificate) {
        if self.high_qc.as_ref().is_none_or(|h| qc.round > h.round) {
            self.high_qc = Some(qc.clone());
        }
    }

    /// Update `locked_qc` on PreCommitQC — THE LOCK.
    /// Only updates if strictly higher round.
    pub fn update_locked_qc(&mut self, qc: &QuorumCertificate) {
        if self.locked_qc.as_ref().is_none_or(|l| qc.round > l.round) {
            self.locked_qc = Some(qc.clone());
        }
    }
}

// ── Test utilities ──────────────────────────────────────────────────────────

/// Chain-aware ancestry checker for tests.
/// Tracks `block_hash → parent_hash` and walks the chain.
#[cfg(test)]
pub mod test_util {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    pub struct MockAncestry {
        parents: HashMap<[u8; 32], [u8; 32]>,
    }

    impl MockAncestry {
        pub fn new() -> Self {
            Self {
                parents: HashMap::new(),
            }
        }

        /// Register `child` as having `parent` as its parent.
        pub fn add_block(&mut self, child: [u8; 32], parent: [u8; 32]) {
            self.parents.insert(child, parent);
        }
    }

    impl AncestryChecker for MockAncestry {
        fn is_ancestor(&self, ancestor: &[u8; 32], descendant: &[u8; 32]) -> bool {
            if ancestor == descendant {
                return true;
            }
            let mut current = *descendant;
            for _ in 0..1000 {
                match self.parents.get(&current) {
                    Some(parent) => {
                        if parent == ancestor {
                            return true;
                        }
                        current = *parent;
                    }
                    None => return false,
                }
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_util::MockAncestry;
    use super::*;

    fn block_hash(id: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = id;
        h
    }

    fn make_qc(phase: BftPhase, hash_id: u8, round: u64) -> QuorumCertificate {
        QuorumCertificate {
            block_hash: block_hash(hash_id),
            round,
            phase,
            votes: vec![],
        }
    }

    fn chain_abc() -> MockAncestry {
        // genesis(0x00) ← A(0xAA) ← B(0xBB) ← C(0xCC)
        //                         ← D(0xDD) (sibling of B, same parent A)
        let mut m = MockAncestry::new();
        m.add_block(block_hash(0xAA), block_hash(0x00));
        m.add_block(block_hash(0xBB), block_hash(0xAA));
        m.add_block(block_hash(0xCC), block_hash(0xBB));
        m.add_block(block_hash(0xDD), block_hash(0xAA)); // sibling of B
        m
    }

    // ── Monotonicity ────────────────────────────────────────────────

    #[test]
    fn rejects_vote_in_same_round() {
        let mut s = SafetyState::new();
        s.record_vote(5);
        let r = s.safe_to_vote(5, &block_hash(1), None, &AlwaysExtends);
        assert!(matches!(
            r,
            Err(SafetyError::RoundNotMonotonic {
                proposal: 5,
                last_voted: 5
            })
        ));
    }

    #[test]
    fn rejects_vote_in_earlier_round() {
        let mut s = SafetyState::new();
        s.record_vote(5);
        let r = s.safe_to_vote(3, &block_hash(1), None, &AlwaysExtends);
        assert!(matches!(r, Err(SafetyError::RoundNotMonotonic { .. })));
    }

    #[test]
    fn accepts_vote_in_higher_round() {
        let mut s = SafetyState::new();
        s.record_vote(5);
        assert!(s
            .safe_to_vote(6, &block_hash(1), None, &AlwaysExtends)
            .is_ok());
    }

    #[test]
    fn accepts_first_vote_ever() {
        let s = SafetyState::new();
        assert!(s
            .safe_to_vote(0, &block_hash(1), None, &AlwaysExtends)
            .is_ok());
    }

    // ── No lock ─────────────────────────────────────────────────────

    #[test]
    fn no_lock_accepts_anything() {
        let s = SafetyState::new();
        assert!(s
            .safe_to_vote(0, &block_hash(0xFF), None, &AlwaysExtends)
            .is_ok());
    }

    // ── Lock + ancestry ─────────────────────────────────────────────

    #[test]
    fn locked_accepts_descendant() {
        let mut s = SafetyState::new();
        // Locked on A
        s.update_locked_qc(&make_qc(BftPhase::PreCommit, 0xAA, 0));
        let chain = chain_abc();
        // B is child of A → safe
        assert!(s.safe_to_vote(1, &block_hash(0xBB), None, &chain).is_ok());
        // C is grandchild of A → safe
        assert!(s.safe_to_vote(2, &block_hash(0xCC), None, &chain).is_ok());
    }

    #[test]
    fn locked_rejects_sibling() {
        let mut s = SafetyState::new();
        // Locked on B (child of A)
        s.update_locked_qc(&make_qc(BftPhase::PreCommit, 0xBB, 0));
        let chain = chain_abc();
        // D is sibling of B (same parent A) — NOT a descendant of B → reject
        let r = s.safe_to_vote(1, &block_hash(0xDD), None, &chain);
        assert!(matches!(r, Err(SafetyError::LockedConflict { .. })));
    }

    #[test]
    fn locked_rejects_unrelated_block() {
        let mut s = SafetyState::new();
        s.update_locked_qc(&make_qc(BftPhase::PreCommit, 0xAA, 0));
        let chain = chain_abc();
        // 0xFF not in chain at all
        let r = s.safe_to_vote(1, &block_hash(0xFF), None, &chain);
        assert!(matches!(r, Err(SafetyError::LockedConflict { .. })));
    }

    // ── Lock + justify_qc (safe unlock) ─────────────────────────────

    #[test]
    fn higher_justify_qc_unlocks() {
        let mut s = SafetyState::new();
        s.update_locked_qc(&make_qc(BftPhase::PreCommit, 0xAA, 5));
        let chain = chain_abc();
        // justify_qc.round=6 > lock.round=5 → unlock, accept even unrelated block
        let jqc = make_qc(BftPhase::Prepare, 0xFF, 6);
        assert!(s
            .safe_to_vote(7, &block_hash(0xFF), Some(&jqc), &chain)
            .is_ok());
    }

    #[test]
    fn equal_justify_qc_does_not_unlock() {
        let mut s = SafetyState::new();
        s.update_locked_qc(&make_qc(BftPhase::PreCommit, 0xAA, 5));
        let chain = chain_abc();
        // justify_qc.round=5 == lock.round=5 → does NOT unlock
        let jqc = make_qc(BftPhase::Prepare, 0xFF, 5);
        let r = s.safe_to_vote(6, &block_hash(0xFF), Some(&jqc), &chain);
        assert!(matches!(r, Err(SafetyError::LockedConflict { .. })));
    }

    #[test]
    fn lower_justify_qc_does_not_unlock() {
        let mut s = SafetyState::new();
        s.update_locked_qc(&make_qc(BftPhase::PreCommit, 0xAA, 5));
        let chain = chain_abc();
        // justify_qc.round=3 < lock.round=5 → stale, does not unlock
        let jqc = make_qc(BftPhase::Prepare, 0xFF, 3);
        let r = s.safe_to_vote(6, &block_hash(0xFF), Some(&jqc), &chain);
        assert!(matches!(r, Err(SafetyError::LockedConflict { .. })));
    }

    // ── high_qc / locked_qc updates ─────────────────────────────────

    #[test]
    fn high_qc_only_increases() {
        let mut s = SafetyState::new();
        s.update_high_qc(&make_qc(BftPhase::Prepare, 0xAA, 5));
        assert_eq!(s.high_qc().unwrap().round, 5);

        s.update_high_qc(&make_qc(BftPhase::Prepare, 0xBB, 3));
        assert_eq!(s.high_qc().unwrap().round, 5); // unchanged

        s.update_high_qc(&make_qc(BftPhase::Prepare, 0xCC, 7));
        assert_eq!(s.high_qc().unwrap().round, 7); // updated
    }

    #[test]
    fn locked_qc_only_increases() {
        let mut s = SafetyState::new();
        s.update_locked_qc(&make_qc(BftPhase::PreCommit, 0xAA, 5));
        assert_eq!(s.locked_qc().unwrap().round, 5);

        s.update_locked_qc(&make_qc(BftPhase::PreCommit, 0xBB, 3));
        assert_eq!(s.locked_qc().unwrap().round, 5); // unchanged

        s.update_locked_qc(&make_qc(BftPhase::PreCommit, 0xCC, 7));
        assert_eq!(s.locked_qc().unwrap().round, 7); // updated
    }

    // ── MockAncestry ────────────────────────────────────────────────

    #[test]
    fn ancestry_reflexive() {
        let chain = chain_abc();
        assert!(chain.is_ancestor(&block_hash(0xAA), &block_hash(0xAA)));
    }

    #[test]
    fn ancestry_direct_parent() {
        let chain = chain_abc();
        assert!(chain.is_ancestor(&block_hash(0xAA), &block_hash(0xBB)));
    }

    #[test]
    fn ancestry_grandparent() {
        let chain = chain_abc();
        assert!(chain.is_ancestor(&block_hash(0xAA), &block_hash(0xCC)));
    }

    #[test]
    fn ancestry_not_reverse() {
        let chain = chain_abc();
        assert!(!chain.is_ancestor(&block_hash(0xCC), &block_hash(0xAA)));
    }

    #[test]
    fn ancestry_sibling_not_ancestor() {
        let chain = chain_abc();
        assert!(!chain.is_ancestor(&block_hash(0xBB), &block_hash(0xDD)));
        assert!(!chain.is_ancestor(&block_hash(0xDD), &block_hash(0xBB)));
    }
}
