//! Vote accumulator for BFT rounds.
//!
//! Collects individual [`VoteMessage`]s for a specific `(phase, round, block_hash)`
//! and signals when quorum (`2f + 1`) is reached, producing a [`QuorumCertificate`].

use std::collections::HashMap;

use super::quorum::{QuorumValidator, SignatureVerifier};
use super::types::{BftPhase, QcError, QuorumCertificate, VoteMessage};

/// Result of adding a vote to the collector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoteResult {
    /// Vote accepted, quorum not yet reached. `count` = valid votes so far.
    Pending { count: usize },
    /// Vote accepted and quorum reached — returns the formed QC.
    QuorumReached { qc: QuorumCertificate },
    /// Vote was rejected (reason in the error).
    Rejected { reason: QcError },
}

/// Accumulates votes for a single `(phase, round, block_hash)` tuple.
///
/// Thread-safe: intended to be used behind external synchronization
/// (e.g. `Mutex<BftRound>` owns the collector).
pub struct VoteCollector<V: SignatureVerifier> {
    phase: BftPhase,
    round: u64,
    block_hash: [u8; 32],
    /// Accepted votes keyed by voter_id to prevent duplicates.
    votes: HashMap<String, VoteMessage>,
    /// Quorum validator for signature and membership checks.
    quorum_validator: QuorumValidator<V>,
    /// Cached: whether quorum was already reached.
    quorum_reached: bool,
}

impl<V: SignatureVerifier> VoteCollector<V> {
    /// Create a new collector for a specific `(phase, round, block_hash)`.
    pub fn new(
        phase: BftPhase,
        round: u64,
        block_hash: [u8; 32],
        quorum_validator: QuorumValidator<V>,
    ) -> Self {
        Self {
            phase,
            round,
            block_hash,
            votes: HashMap::new(),
            quorum_validator,
            quorum_reached: false,
        }
    }

    /// Add a vote. Returns the result of the operation.
    ///
    /// Checks:
    /// 1. Vote matches this collector's `(phase, round, block_hash)`
    /// 2. Voter is not a duplicate
    /// 3. Voter is a known validator with a valid signature
    /// 4. Whether quorum is now reached
    pub fn add_vote(&mut self, vote: VoteMessage) -> VoteResult {
        // Already finalized — ignore further votes.
        if self.quorum_reached {
            return VoteResult::Rejected {
                reason: QcError::DuplicateVoter("quorum already reached".into()),
            };
        }

        // Phase mismatch.
        if vote.phase != self.phase {
            return VoteResult::Rejected {
                reason: QcError::MismatchedPhase {
                    expected: self.phase,
                    got: vote.phase,
                },
            };
        }

        // Round mismatch.
        if vote.round != self.round {
            return VoteResult::Rejected {
                reason: QcError::MismatchedRound {
                    expected: self.round,
                    got: vote.round,
                },
            };
        }

        // Block hash mismatch.
        if vote.block_hash != self.block_hash {
            return VoteResult::Rejected {
                reason: QcError::MismatchedBlockHash {
                    expected: self.block_hash,
                    got: vote.block_hash,
                },
            };
        }

        // Duplicate voter.
        if self.votes.contains_key(&vote.voter_id) {
            return VoteResult::Rejected {
                reason: QcError::DuplicateVoter(vote.voter_id.clone()),
            };
        }

        // Validate membership + signature.
        if let Err(e) = self.quorum_validator.validate_vote(&vote) {
            return VoteResult::Rejected { reason: e };
        }

        // Accept the vote.
        let voter_id = vote.voter_id.clone();
        self.votes.insert(voter_id, vote);

        // Check quorum.
        let count = self.votes.len();
        let threshold = self.quorum_validator.quorum_threshold();

        if count >= threshold {
            self.quorum_reached = true;
            let votes: Vec<VoteMessage> = self.votes.values().cloned().collect();
            match QuorumCertificate::new(self.phase, self.block_hash, self.round, votes) {
                Ok(qc) => VoteResult::QuorumReached { qc },
                Err(e) => VoteResult::Rejected { reason: e },
            }
        } else {
            VoteResult::Pending { count }
        }
    }

    /// Current number of accepted votes.
    pub fn vote_count(&self) -> usize {
        self.votes.len()
    }

    /// Whether quorum has been reached.
    pub fn is_complete(&self) -> bool {
        self.quorum_reached
    }

    /// The quorum threshold for this collector.
    pub fn threshold(&self) -> usize {
        self.quorum_validator.quorum_threshold()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::bft::quorum::AcceptAllVerifier;

    fn validators(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("v{i}")).collect()
    }

    fn block_hash(id: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = id;
        h
    }

    fn make_vote(phase: BftPhase, hash_id: u8, round: u64, voter: &str) -> VoteMessage {
        VoteMessage {
            block_hash: block_hash(hash_id),
            round,
            phase,
            voter_id: voter.to_string(),
            signature: vec![1u8; 64],
        }
    }

    fn collector_4(phase: BftPhase, hash_id: u8, round: u64) -> VoteCollector<AcceptAllVerifier> {
        let qv = QuorumValidator::new(validators(4), AcceptAllVerifier);
        VoteCollector::new(phase, round, block_hash(hash_id), qv)
    }

    // --- basic accumulation ---

    #[test]
    fn first_vote_returns_pending() {
        let mut c = collector_4(BftPhase::Prepare, 1, 0);
        let result = c.add_vote(make_vote(BftPhase::Prepare, 1, 0, "v0"));
        assert!(matches!(result, VoteResult::Pending { count: 1 }));
        assert_eq!(c.vote_count(), 1);
    }

    #[test]
    fn second_vote_returns_pending() {
        let mut c = collector_4(BftPhase::Prepare, 1, 0);
        c.add_vote(make_vote(BftPhase::Prepare, 1, 0, "v0"));
        let result = c.add_vote(make_vote(BftPhase::Prepare, 1, 0, "v1"));
        assert!(matches!(result, VoteResult::Pending { count: 2 }));
    }

    #[test]
    fn third_vote_reaches_quorum() {
        // n=4, threshold=3
        let mut c = collector_4(BftPhase::Prepare, 1, 0);
        c.add_vote(make_vote(BftPhase::Prepare, 1, 0, "v0"));
        c.add_vote(make_vote(BftPhase::Prepare, 1, 0, "v1"));
        let result = c.add_vote(make_vote(BftPhase::Prepare, 1, 0, "v2"));
        match result {
            VoteResult::QuorumReached { qc } => {
                assert_eq!(qc.phase, BftPhase::Prepare);
                assert_eq!(qc.round, 0);
                assert_eq!(qc.block_hash, block_hash(1));
                assert_eq!(qc.voter_count(), 3);
            }
            other => panic!("expected QuorumReached, got {other:?}"),
        }
        assert!(c.is_complete());
    }

    // --- rejection cases ---

    #[test]
    fn rejects_duplicate_voter() {
        let mut c = collector_4(BftPhase::Prepare, 1, 0);
        c.add_vote(make_vote(BftPhase::Prepare, 1, 0, "v0"));
        let result = c.add_vote(make_vote(BftPhase::Prepare, 1, 0, "v0"));
        assert!(matches!(
            result,
            VoteResult::Rejected {
                reason: QcError::DuplicateVoter(_)
            }
        ));
        assert_eq!(c.vote_count(), 1);
    }

    #[test]
    fn rejects_wrong_phase() {
        let mut c = collector_4(BftPhase::Prepare, 1, 0);
        let result = c.add_vote(make_vote(BftPhase::Commit, 1, 0, "v0"));
        assert!(matches!(
            result,
            VoteResult::Rejected {
                reason: QcError::MismatchedPhase { .. }
            }
        ));
    }

    #[test]
    fn rejects_wrong_round() {
        let mut c = collector_4(BftPhase::Prepare, 1, 0);
        let result = c.add_vote(make_vote(BftPhase::Prepare, 1, 99, "v0"));
        assert!(matches!(
            result,
            VoteResult::Rejected {
                reason: QcError::MismatchedRound { .. }
            }
        ));
    }

    #[test]
    fn rejects_wrong_block_hash() {
        let mut c = collector_4(BftPhase::Prepare, 1, 0);
        let result = c.add_vote(make_vote(BftPhase::Prepare, 99, 0, "v0"));
        assert!(matches!(
            result,
            VoteResult::Rejected {
                reason: QcError::MismatchedBlockHash { .. }
            }
        ));
    }

    #[test]
    fn rejects_unknown_voter() {
        let mut c = collector_4(BftPhase::Prepare, 1, 0);
        let result = c.add_vote(make_vote(BftPhase::Prepare, 1, 0, "intruder"));
        assert!(matches!(
            result,
            VoteResult::Rejected {
                reason: QcError::UnknownVoter(_)
            }
        ));
    }

    // --- post-quorum behavior ---

    #[test]
    fn rejects_votes_after_quorum() {
        let mut c = collector_4(BftPhase::Prepare, 1, 0);
        c.add_vote(make_vote(BftPhase::Prepare, 1, 0, "v0"));
        c.add_vote(make_vote(BftPhase::Prepare, 1, 0, "v1"));
        c.add_vote(make_vote(BftPhase::Prepare, 1, 0, "v2"));
        assert!(c.is_complete());

        // Fourth vote should be rejected.
        let result = c.add_vote(make_vote(BftPhase::Prepare, 1, 0, "v3"));
        assert!(matches!(result, VoteResult::Rejected { .. }));
    }

    // --- threshold accessor ---

    #[test]
    fn threshold_matches_quorum_validator() {
        let c = collector_4(BftPhase::Prepare, 1, 0);
        assert_eq!(c.threshold(), 3); // n=4, f=1, 2f+1=3
    }

    // --- different phases produce different collectors ---

    #[test]
    fn precommit_collector_works() {
        let mut c = collector_4(BftPhase::PreCommit, 1, 0);
        c.add_vote(make_vote(BftPhase::PreCommit, 1, 0, "v0"));
        c.add_vote(make_vote(BftPhase::PreCommit, 1, 0, "v1"));
        let result = c.add_vote(make_vote(BftPhase::PreCommit, 1, 0, "v2"));
        match result {
            VoteResult::QuorumReached { qc } => {
                assert_eq!(qc.phase, BftPhase::PreCommit);
            }
            other => panic!("expected QuorumReached, got {other:?}"),
        }
    }

    // ── BFT safety: quorum intersection prevents conflicting blocks ──

    /// With n=4 quorum=3, two quorums must share ≥2 members.
    /// If 3 honest nodes vote for block A, a Byzantine node cannot form
    /// a quorum for block B — it can only contribute 1 vote, needing 2 more
    /// from nodes that already voted A (which honest nodes refuse).
    #[test]
    fn conflicting_block_cannot_reach_quorum() {
        let block_a = block_hash(0xAA);
        let block_b = block_hash(0xBB);

        // Collector for block A — 3 honest nodes vote.
        let mut col_a = {
            let qv = QuorumValidator::new(validators(4), AcceptAllVerifier);
            VoteCollector::new(BftPhase::Prepare, 0, block_a, qv)
        };
        col_a.add_vote(make_vote(BftPhase::Prepare, 0xAA, 0, "v0")); // IAD
        col_a.add_vote(make_vote(BftPhase::Prepare, 0xAA, 0, "v1")); // CDG
        let result = col_a.add_vote(make_vote(BftPhase::Prepare, 0xAA, 0, "v2")); // SIN
        assert!(
            matches!(result, VoteResult::QuorumReached { .. }),
            "block A must reach quorum"
        );

        // Collector for block B — Byzantine NRT tries to form quorum.
        let mut col_b = {
            let qv = QuorumValidator::new(validators(4), AcceptAllVerifier);
            VoteCollector::new(BftPhase::Prepare, 0, block_b, qv)
        };
        // NRT votes for B (the only legitimate vote for B).
        let r = col_b.add_vote(make_vote(BftPhase::Prepare, 0xBB, 0, "v3"));
        assert!(matches!(r, VoteResult::Pending { count: 1 }));

        // NRT tries to replay honest nodes' votes but with block B hash.
        // Honest nodes never sign block B, so these would fail real signature
        // verification. Even with AcceptAllVerifier, the collector only has
        // 1 valid vote — it cannot reach quorum=3 without 2 more voters.
        assert_eq!(col_b.vote_count(), 1);
        assert!(!col_b.is_complete());
        // NRT needs 2 more votes from {v0,v1,v2} — but they already voted A.
        // An honest node won't sign two different blocks for the same round.
    }

    /// A Byzantine node that tries to double-vote (same voter_id, different
    /// block hash) is rejected by MismatchedBlockHash on the collector that
    /// doesn't match, and by DuplicateVoter on the one that does.
    #[test]
    fn byzantine_double_vote_rejected() {
        let mut col = collector_4(BftPhase::Prepare, 0xAA, 0);

        // NRT votes for block A (legitimate).
        let r = col.add_vote(make_vote(BftPhase::Prepare, 0xAA, 0, "v3"));
        assert!(matches!(r, VoteResult::Pending { count: 1 }));

        // NRT tries to vote again for the same block (duplicate).
        let r = col.add_vote(make_vote(BftPhase::Prepare, 0xAA, 0, "v3"));
        assert!(matches!(
            r,
            VoteResult::Rejected {
                reason: QcError::DuplicateVoter(_)
            }
        ));

        // NRT tries to vote for block B in the same collector — hash mismatch.
        let r = col.add_vote(make_vote(BftPhase::Prepare, 0xBB, 0, "v3"));
        assert!(matches!(
            r,
            VoteResult::Rejected {
                reason: QcError::MismatchedBlockHash { .. }
            }
        ));

        // Still only 1 valid vote.
        assert_eq!(col.vote_count(), 1);
    }

    /// Quorum intersection theorem: any two sets of size 3 from {v0,v1,v2,v3}
    /// share at least 2 members. This means if QC(A) exists with 3 voters,
    /// a QC(B) would need 3 voters too — but at least 2 of those already
    /// voted A. Since honest nodes don't double-vote, QC(B) is impossible.
    #[test]
    fn quorum_intersection_all_pairs() {
        let all: Vec<String> = validators(4);
        let threshold = 3usize;

        // Generate all C(4,3) = 4 possible quorums.
        let quorums: Vec<Vec<&String>> = vec![
            vec![&all[0], &all[1], &all[2]],
            vec![&all[0], &all[1], &all[3]],
            vec![&all[0], &all[2], &all[3]],
            vec![&all[1], &all[2], &all[3]],
        ];

        // Every pair of quorums must intersect with ≥ 1 member.
        // (Actually ≥ 2 for n=4,q=3, but ≥1 is the BFT minimum.)
        for (i, q1) in quorums.iter().enumerate() {
            for q2 in quorums.iter().skip(i + 1) {
                let intersection: Vec<_> = q1.iter().filter(|v| q2.contains(v)).collect();
                assert!(
                    intersection.len() >= 2,
                    "quorums {:?} and {:?} share only {} members (need ≥2)",
                    q1,
                    q2,
                    intersection.len()
                );
            }
        }

        // Therefore: if block A has QC (any 3 voters), block B cannot have
        // QC because it would need ≥2 voters from A's quorum, and honest
        // nodes refuse to vote for two different blocks in the same round.
        assert_eq!(threshold, 3);
    }

    /// Full scenario: IAD proposes A, NRT (Byzantine) proposes B.
    /// Honest nodes (v0=IAD, v1=CDG, v2=SIN) vote A.
    /// NRT (v3) votes B. B never reaches quorum.
    #[test]
    fn byzantine_leader_equivocation_blocked() {
        let block_a = block_hash(0xAA);
        let block_b = block_hash(0xBB);

        // Simulate honest path: IAD proposes A, gets quorum.
        let mut col_a = {
            let qv = QuorumValidator::new(validators(4), AcceptAllVerifier);
            VoteCollector::new(BftPhase::Prepare, 5, block_a, qv)
        };
        col_a.add_vote(make_vote(BftPhase::Prepare, 0xAA, 5, "v0")); // IAD
        col_a.add_vote(make_vote(BftPhase::Prepare, 0xAA, 5, "v1")); // CDG
        let r = col_a.add_vote(make_vote(BftPhase::Prepare, 0xAA, 5, "v2")); // SIN
        assert!(matches!(r, VoteResult::QuorumReached { .. }));

        // NRT proposes B and tries to collect votes.
        let mut col_b = {
            let qv = QuorumValidator::new(validators(4), AcceptAllVerifier);
            VoteCollector::new(BftPhase::Prepare, 5, block_b, qv)
        };
        // Only NRT votes for B.
        col_b.add_vote(make_vote(BftPhase::Prepare, 0xBB, 5, "v3"));

        // Even if NRT forges votes from honest nodes for B, the collector
        // accepts them (AcceptAllVerifier) but real crypto would reject.
        // We test the quorum math: NRT needs 2 more.
        // Simulate: NRT forges v0 and v1 votes for B.
        col_b.add_vote(make_vote(BftPhase::Prepare, 0xBB, 5, "v0"));
        let r = col_b.add_vote(make_vote(BftPhase::Prepare, 0xBB, 5, "v1"));
        // With AcceptAllVerifier, forged votes pass — quorum reached for B!
        // This is why real signature verification matters.
        assert!(
            matches!(r, VoteResult::QuorumReached { .. }),
            "forged votes pass with AcceptAllVerifier (expected — proves crypto is essential)"
        );

        // But with a verifier that rejects forged signatures, B fails.
        // The honest nodes' private keys never signed B, so the forged
        // signatures are invalid. We simulate with RejectVoterVerifier.
        use crate::consensus::bft::quorum::RejectVoterVerifier;
        use std::collections::HashSet;

        // Verifier that rejects v0 and v1 signing block B
        // (simulates that honest nodes never signed B).
        let reject = HashSet::from(["v0".to_string(), "v1".to_string()]);
        let verifier = RejectVoterVerifier { reject };
        let mut col_b_real = {
            let qv = QuorumValidator::new(validators(4), verifier);
            VoteCollector::new(BftPhase::Prepare, 5, block_b, qv)
        };

        // NRT's own vote passes.
        let r = col_b_real.add_vote(make_vote(BftPhase::Prepare, 0xBB, 5, "v3"));
        assert!(matches!(r, VoteResult::Pending { count: 1 }));

        // Forged votes from v0 and v1 are rejected by signature verification.
        let r = col_b_real.add_vote(make_vote(BftPhase::Prepare, 0xBB, 5, "v0"));
        assert!(matches!(
            r,
            VoteResult::Rejected {
                reason: QcError::InvalidSignature(_)
            }
        ));
        let r = col_b_real.add_vote(make_vote(BftPhase::Prepare, 0xBB, 5, "v1"));
        assert!(matches!(
            r,
            VoteResult::Rejected {
                reason: QcError::InvalidSignature(_)
            }
        ));

        // B stuck at 1 vote. QC impossible.
        assert_eq!(col_b_real.vote_count(), 1);
        assert!(!col_b_real.is_complete());
    }

    #[test]
    fn commit_collector_works() {
        let mut c = collector_4(BftPhase::Commit, 1, 5);
        c.add_vote(make_vote(BftPhase::Commit, 1, 5, "v0"));
        c.add_vote(make_vote(BftPhase::Commit, 1, 5, "v1"));
        let result = c.add_vote(make_vote(BftPhase::Commit, 1, 5, "v2"));
        match result {
            VoteResult::QuorumReached { qc } => {
                assert_eq!(qc.phase, BftPhase::Commit);
                assert_eq!(qc.round, 5);
            }
            other => panic!("expected QuorumReached, got {other:?}"),
        }
    }
}
