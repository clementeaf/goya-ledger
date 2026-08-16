//! Round manager — orchestrates consecutive BFT rounds with leader rotation
//! and timeout-based liveness.
//!
//! Sits above [`BftRound`] and handles:
//! - Round-robin leader election from the validator set
//! - Timeout detection and view change (advance to next round with new leader)
//! - Tracking the highest committed QC for chain continuity

use super::quorum::SignatureVerifier;
use super::round::{BftRound, RoundAction, RoundEvent, RoundState};
use super::types::QuorumCertificate;

/// Configuration for the round manager.
#[derive(Debug, Clone)]
pub struct RoundManagerConfig {
    /// Base timeout in milliseconds for a single round.
    /// Doubles on each consecutive timeout (exponential backoff).
    pub base_timeout_ms: u64,
    /// Maximum timeout in milliseconds (backoff cap).
    pub max_timeout_ms: u64,
}

impl Default for RoundManagerConfig {
    fn default() -> Self {
        Self {
            base_timeout_ms: 3000,
            max_timeout_ms: 30_000,
        }
    }
}

/// Actions emitted by the round manager to the network layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagerAction {
    /// A round action from the current BftRound.
    Round(RoundAction),
    /// A new round started — caller should reset their timeout timer.
    NewRound {
        round: u64,
        leader_id: String,
        timeout_ms: u64,
    },
    /// No action.
    None,
}

/// Manages consecutive BFT rounds with leader rotation and liveness timeouts.
pub struct RoundManager<V: SignatureVerifier + Clone> {
    node_id: String,
    validators: Vec<String>,
    verifier: V,
    config: RoundManagerConfig,
    /// Current round number.
    current_round: u64,
    /// The active round state machine.
    current: Option<BftRound<V>>,
    /// Number of consecutive timeouts (for exponential backoff).
    consecutive_timeouts: u32,
    /// Highest committed QC seen so far.
    highest_commit_qc: Option<QuorumCertificate>,
}

impl<V: SignatureVerifier + Clone> RoundManager<V> {
    /// Create a new round manager.
    pub fn new(
        node_id: String,
        validators: Vec<String>,
        verifier: V,
        config: RoundManagerConfig,
    ) -> Self {
        Self {
            node_id,
            validators,
            verifier,
            config,
            current_round: 0,
            current: None,
            consecutive_timeouts: 0,
            highest_commit_qc: None,
        }
    }

    /// Current round number.
    pub fn current_round(&self) -> u64 {
        self.current_round
    }

    /// The leader for a given round (round-robin over validators).
    pub fn leader_for_round(&self, round: u64) -> &str {
        if self.validators.is_empty() {
            return "";
        }
        let idx = (round as usize) % self.validators.len();
        &self.validators[idx]
    }

    /// The leader for the current round.
    pub fn current_leader(&self) -> &str {
        self.leader_for_round(self.current_round)
    }

    /// Whether this node is leader for the current round.
    pub fn is_current_leader(&self) -> bool {
        self.current_leader() == self.node_id
    }

    /// Current timeout in ms (with exponential backoff).
    pub fn current_timeout_ms(&self) -> u64 {
        let timeout = self.config.base_timeout_ms * 2u64.saturating_pow(self.consecutive_timeouts);
        timeout.min(self.config.max_timeout_ms)
    }

    /// The highest committed QC.
    pub fn highest_commit_qc(&self) -> Option<&QuorumCertificate> {
        self.highest_commit_qc.as_ref()
    }

    /// State of the current round (if active).
    pub fn round_state(&self) -> Option<RoundState> {
        self.current.as_ref().map(|r| r.state())
    }

    /// Start or advance to a specific round.
    ///
    /// Creates a new `BftRound`, selects the leader via round-robin,
    /// and returns a `NewRound` action so the caller can set their timer.
    /// If this node is the leader, also returns a `StartAsLeader` prompt.
    pub fn start_round(&mut self, round: u64) -> ManagerAction {
        self.current_round = round;
        let leader = self.leader_for_round(round).to_string();

        let bft_round = BftRound::new(
            round,
            self.node_id.clone(),
            leader.clone(),
            self.validators.clone(),
            self.verifier.clone(),
        );
        self.current = Some(bft_round);

        ManagerAction::NewRound {
            round,
            leader_id: leader,
            timeout_ms: self.current_timeout_ms(),
        }
    }

    /// Start round 0 (convenience for initialization).
    pub fn start(&mut self) -> ManagerAction {
        self.start_round(0)
    }

    /// Feed an event to the current round. Returns the resulting action.
    pub fn process_event(&mut self, event: RoundEvent) -> ManagerAction {
        let round = match self.current.as_mut() {
            Some(r) => r,
            None => return ManagerAction::None,
        };

        let action = round.process(event);

        // If a Decide action, update highest QC and reset timeout backoff.
        if let RoundAction::Decide { ref commit_qc, .. } = action {
            self.highest_commit_qc = Some(commit_qc.clone());
            self.consecutive_timeouts = 0;
        }

        ManagerAction::Round(action)
    }

    /// Handle a timeout for the current round.
    ///
    /// Increments the backoff counter and advances to the next round with
    /// a new leader. Returns `NewRound` so the caller can reset their timer.
    pub fn on_timeout(&mut self) -> ManagerAction {
        // Notify the current round of the timeout.
        if let Some(ref mut r) = self.current {
            r.process(RoundEvent::Timeout);
        }

        self.consecutive_timeouts += 1;
        let next_round = self.current_round + 1;
        self.start_round(next_round)
    }

    /// Advance to the next round after a successful Decide.
    ///
    /// Resets timeout backoff since progress was made.
    pub fn advance_after_decide(&mut self) -> ManagerAction {
        self.consecutive_timeouts = 0;
        let next_round = self.current_round + 1;
        self.start_round(next_round)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::bft::quorum::AcceptAllVerifier;
    use crate::consensus::bft::round::RoundAction;
    use crate::consensus::bft::types::{BftPhase, VoteMessage};

    fn validators() -> Vec<String> {
        (0..4).map(|i| format!("v{i}")).collect()
    }

    fn manager(node: &str) -> RoundManager<AcceptAllVerifier> {
        RoundManager::new(
            node.into(),
            validators(),
            AcceptAllVerifier,
            RoundManagerConfig::default(),
        )
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

    // --- leader rotation ---

    #[test]
    fn leader_rotates_round_robin() {
        let m = manager("v0");
        assert_eq!(m.leader_for_round(0), "v0");
        assert_eq!(m.leader_for_round(1), "v1");
        assert_eq!(m.leader_for_round(2), "v2");
        assert_eq!(m.leader_for_round(3), "v3");
        assert_eq!(m.leader_for_round(4), "v0"); // wraps
    }

    #[test]
    fn start_returns_new_round_action() {
        let mut m = manager("v0");
        let action = m.start();
        match action {
            ManagerAction::NewRound {
                round,
                leader_id,
                timeout_ms,
            } => {
                assert_eq!(round, 0);
                assert_eq!(leader_id, "v0");
                assert_eq!(timeout_ms, 3000);
            }
            other => panic!("expected NewRound, got {other:?}"),
        }
        assert_eq!(m.current_round(), 0);
    }

    #[test]
    fn is_current_leader_when_round_matches() {
        let mut m = manager("v0");
        m.start_round(0);
        assert!(m.is_current_leader());

        m.start_round(1);
        assert!(!m.is_current_leader()); // v1 is leader for round 1
    }

    // --- timeout & backoff ---

    #[test]
    fn timeout_advances_round() {
        let mut m = manager("v0");
        m.start();
        let action = m.on_timeout();
        match action {
            ManagerAction::NewRound {
                round, leader_id, ..
            } => {
                assert_eq!(round, 1);
                assert_eq!(leader_id, "v1");
            }
            other => panic!("expected NewRound, got {other:?}"),
        }
        assert_eq!(m.current_round(), 1);
    }

    #[test]
    fn timeout_backoff_doubles() {
        let mut m = manager("v0");
        m.start();
        assert_eq!(m.current_timeout_ms(), 3000);

        m.on_timeout(); // consecutive=1
        assert_eq!(m.current_timeout_ms(), 6000);

        m.on_timeout(); // consecutive=2
        assert_eq!(m.current_timeout_ms(), 12000);

        m.on_timeout(); // consecutive=3
        assert_eq!(m.current_timeout_ms(), 24000);

        m.on_timeout(); // consecutive=4 → 48000 capped to 30000
        assert_eq!(m.current_timeout_ms(), 30_000);
    }

    #[test]
    fn backoff_resets_after_decide() {
        let mut m = manager("v0");
        m.start();
        m.on_timeout(); // consecutive=1
        m.on_timeout(); // consecutive=2
        assert_eq!(m.current_timeout_ms(), 12000);

        // Simulate a decide.
        m.advance_after_decide();
        assert_eq!(m.current_timeout_ms(), 3000); // reset
    }

    // --- full flow through manager ---

    #[test]
    fn full_round_via_manager() {
        let mut m = manager("v0");
        m.start();

        // Leader proposes.
        let action = m.process_event(RoundEvent::StartAsLeader {
            block_hash: block_hash(1),
        });
        assert!(matches!(
            action,
            ManagerAction::Round(RoundAction::BroadcastProposal { .. })
        ));

        // Collect votes through all phases.
        for phase in [BftPhase::Prepare, BftPhase::PreCommit, BftPhase::Commit] {
            for voter in &["v0", "v1", "v2"] {
                m.process_event(RoundEvent::Vote(make_vote(phase, 1, 0, voter)));
            }
        }

        assert_eq!(m.round_state(), Some(RoundState::Decided));
        assert!(m.highest_commit_qc().is_some());
        assert_eq!(m.consecutive_timeouts, 0);
    }

    #[test]
    fn follower_receives_proposal_via_manager() {
        let mut m = manager("v1"); // v0 is leader for round 0
        m.start();

        let action = m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(1),
            leader_id: "v0".into(),
        });
        match action {
            ManagerAction::Round(RoundAction::SendVote(vote)) => {
                assert_eq!(vote.voter_id, "v1");
                assert_eq!(vote.phase, BftPhase::Prepare);
            }
            other => panic!("expected SendVote, got {other:?}"),
        }
    }

    #[test]
    fn events_before_start_are_noop() {
        let mut m = manager("v0");
        let action = m.process_event(RoundEvent::Vote(make_vote(BftPhase::Prepare, 1, 0, "v0")));
        assert_eq!(action, ManagerAction::None);
    }

    // --- multiple rounds ---

    // ── Adversarial scenarios ─────────────────────────────────────────

    /// Helper: drive a full Prepare→PreCommit→Commit cycle on a single
    /// manager, feeding votes from the given voters. Returns true if Decide.
    fn drive_full_round(
        m: &mut RoundManager<AcceptAllVerifier>,
        hash_id: u8,
        round: u64,
        voters: &[&str],
    ) -> bool {
        for phase in [BftPhase::Prepare, BftPhase::PreCommit, BftPhase::Commit] {
            for voter in voters {
                let action =
                    m.process_event(RoundEvent::Vote(make_vote(phase, hash_id, round, voter)));
                if matches!(action, ManagerAction::Round(RoundAction::Decide { .. })) {
                    return true;
                }
            }
        }
        false
    }

    // ── Scenario 1: Network partition 2+2 ───────────────────────────
    //
    // Partition: {v0, v1} vs {v2, v3}. Neither side has 3 votes.
    // Chain must halt (no Decide on either side), never fork.
    // On reunion: the combined votes must allow progress.

    #[test]
    fn partition_2_2_halts_no_fork() {
        // Two independent managers simulating the two partitions.
        let mut left_leader = manager("v0"); // v0 is leader of round 0
        let mut right_follower = manager("v2");

        left_leader.start();
        right_follower.start();

        // Leader v0 proposes block A.
        left_leader.process_event(RoundEvent::StartAsLeader {
            block_hash: block_hash(0xAA),
        });

        // Right side receives the proposal (before partition).
        right_follower.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xAA),
            leader_id: "v0".into(),
        });

        // LEFT partition: v0 and v1 vote. Only 2 votes — no quorum.
        for voter in &["v0", "v1"] {
            left_leader.process_event(RoundEvent::Vote(make_vote(
                BftPhase::Prepare,
                0xAA,
                0,
                voter,
            )));
        }
        // Left side stuck in Preparing — no PhaseComplete.
        assert_eq!(left_leader.round_state(), Some(RoundState::Preparing));

        // RIGHT partition: v2 and v3 vote. Only 2 votes — no quorum.
        for voter in &["v2", "v3"] {
            right_follower.process_event(RoundEvent::Vote(make_vote(
                BftPhase::Prepare,
                0xAA,
                0,
                voter,
            )));
        }
        assert_eq!(right_follower.round_state(), Some(RoundState::Preparing));

        // Neither side decided — chain halted, no fork.
        assert_ne!(left_leader.round_state(), Some(RoundState::Decided));
        assert_ne!(right_follower.round_state(), Some(RoundState::Decided));

        // REUNION: left side receives votes from right.
        let action = left_leader.process_event(RoundEvent::Vote(make_vote(
            BftPhase::Prepare,
            0xAA,
            0,
            "v2",
        )));
        // 3 votes now (v0, v1, v2) → Prepare quorum reached!
        assert!(
            matches!(
                action,
                ManagerAction::Round(RoundAction::PhaseComplete {
                    phase: BftPhase::Prepare,
                    ..
                })
            ),
            "reunion should reach Prepare quorum, got {action:?}"
        );

        // Drive through PreCommit and Commit with 3 voters.
        let decided = drive_full_round(&mut left_leader, 0xAA, 0, &["v0", "v1", "v2"]);
        assert!(decided, "should reach Decide after reunion");
        assert_eq!(left_leader.round_state(), Some(RoundState::Decided));

        // Verify: only ONE block was decided (no fork).
        let qc = left_leader.highest_commit_qc().unwrap();
        assert_eq!(qc.block_hash, block_hash(0xAA));
    }

    // ── Scenario 2: Byzantine equivocation ──────────────────────────
    //
    // v3 (Byzantine) votes block A to {v0, v1} and block B to {v2}.
    // Honest nodes each see one hash. Two QCs must not coexist.

    #[test]
    fn byzantine_equivocation_cannot_produce_two_qcs() {
        let block_a = block_hash(0xAA);
        let block_b = block_hash(0xBB);

        // --- Node v0's view: leader proposes A ---
        let mut m_v0 = manager("v0");
        m_v0.start();
        m_v0.process_event(RoundEvent::StartAsLeader {
            block_hash: block_a,
        });

        // v0 sees: v0(A), v1(A), v3(A) — Byzantine v3 sends A to this partition.
        m_v0.process_event(RoundEvent::Vote(make_vote(
            BftPhase::Prepare,
            0xAA,
            0,
            "v0",
        )));
        m_v0.process_event(RoundEvent::Vote(make_vote(
            BftPhase::Prepare,
            0xAA,
            0,
            "v1",
        )));
        let action = m_v0.process_event(RoundEvent::Vote(make_vote(
            BftPhase::Prepare,
            0xAA,
            0,
            "v3",
        )));
        // 3 votes for A → Prepare quorum.
        assert!(matches!(
            action,
            ManagerAction::Round(RoundAction::PhaseComplete {
                phase: BftPhase::Prepare,
                ..
            })
        ));

        // --- Node v2's view: Byzantine v3 sent vote for B ---
        let mut m_v2 = manager("v2");
        m_v2.start();
        m_v2.process_event(RoundEvent::Proposal {
            block_hash: block_a, // v2 received the real proposal (block A)
            leader_id: "v0".into(),
        });

        // v2 votes A (honest). v3 sends B to v2.
        m_v2.process_event(RoundEvent::Vote(make_vote(
            BftPhase::Prepare,
            0xAA,
            0,
            "v2",
        )));
        // v3's vote for B is rejected by v2's collector (hash mismatch with A).
        let action = m_v2.process_event(RoundEvent::Vote(make_vote(
            BftPhase::Prepare,
            0xBB,
            0,
            "v3",
        )));
        assert!(
            matches!(action, ManagerAction::Round(RoundAction::None)),
            "vote for wrong block hash must be rejected"
        );

        // v2 only has 1 valid vote (itself). Cannot form QC for B.
        // v2 also cannot form QC for A without 2 more votes.
        assert_eq!(m_v2.round_state(), Some(RoundState::Preparing));

        // Key invariant: QC(A) exists (on v0's side), QC(B) does NOT exist.
        // The Byzantine node cannot cause a fork — at most it can delay v2.

        // Now: can v3 somehow help form QC(B) on a separate collector?
        // Even with a dedicated B-collector, v3 only has 1 vote (itself).
        // Needs 2 more from {v0, v1, v2} — all voted A. Impossible.
        use crate::consensus::bft::quorum::QuorumValidator;
        use crate::consensus::bft::vote_collector::VoteCollector;

        let mut col_b = VoteCollector::new(
            BftPhase::Prepare,
            0,
            block_b,
            QuorumValidator::new(validators(), AcceptAllVerifier),
        );
        col_b.add_vote(make_vote(BftPhase::Prepare, 0xBB, 0, "v3"));
        assert_eq!(col_b.vote_count(), 1);
        assert!(!col_b.is_complete());
        // QC(B) impossible: 1/3 quorum. Byzantine equivocation blocked.
    }

    // ── Scenario 3: Leader death during consensus ───────────────────
    //
    // v0 (leader round 0) proposes A. Gets Prepare votes from v1, v2.
    // v0 dies after Prepare (before PreCommit/Commit).
    // Timeout → round 1, new leader v1. v1 proposes and gets Decide
    // without double-committing A from round 0.

    #[test]
    fn leader_death_after_prepare_recovers_without_double_commit() {
        // Simulate from v1's perspective (v1 survives the leader death).
        let mut m = manager("v1");
        m.start(); // round 0, leader = v0

        // v1 receives proposal from v0.
        m.process_event(RoundEvent::Proposal {
            block_hash: block_hash(0xAA),
            leader_id: "v0".into(),
        });

        // Prepare votes arrive from v0, v1, v2. v1's own vote was already
        // returned as SendVote; here we simulate all votes arriving.
        m.process_event(RoundEvent::Vote(make_vote(
            BftPhase::Prepare,
            0xAA,
            0,
            "v0",
        )));
        m.process_event(RoundEvent::Vote(make_vote(
            BftPhase::Prepare,
            0xAA,
            0,
            "v1",
        )));
        let action = m.process_event(RoundEvent::Vote(make_vote(
            BftPhase::Prepare,
            0xAA,
            0,
            "v2",
        )));
        assert!(matches!(
            action,
            ManagerAction::Round(RoundAction::PhaseComplete {
                phase: BftPhase::Prepare,
                ..
            })
        ));
        assert_eq!(m.round_state(), Some(RoundState::PreCommitting));

        // v0 DIES here. No more votes from v0 for PreCommit/Commit.
        // Only v1 and v2 can vote PreCommit → 2 votes < quorum=3.
        m.process_event(RoundEvent::Vote(make_vote(
            BftPhase::PreCommit,
            0xAA,
            0,
            "v1",
        )));
        m.process_event(RoundEvent::Vote(make_vote(
            BftPhase::PreCommit,
            0xAA,
            0,
            "v2",
        )));
        // Still PreCommitting — no quorum.
        assert_eq!(m.round_state(), Some(RoundState::PreCommitting));

        // TIMEOUT: round 0 failed. Advance to round 1.
        let action = m.on_timeout();
        match &action {
            ManagerAction::NewRound {
                round, leader_id, ..
            } => {
                assert_eq!(*round, 1);
                assert_eq!(leader_id, "v1"); // v1 is new leader!
            }
            other => panic!("expected NewRound, got {other:?}"),
        }

        // Round 0 block A was NOT decided (no CommitQC).
        assert!(
            m.highest_commit_qc().is_none(),
            "block A must NOT be committed"
        );

        // v1 (new leader) proposes block B in round 1.
        m.process_event(RoundEvent::StartAsLeader {
            block_hash: block_hash(0xBB),
        });

        // Drive full round with v1, v2, v3 (v0 is dead).
        let decided = drive_full_round(&mut m, 0xBB, 1, &["v1", "v2", "v3"]);
        assert!(decided, "round 1 should reach Decide with 3 live nodes");
        assert_eq!(m.round_state(), Some(RoundState::Decided));

        // Verify: only block B was committed (no double-commit of A).
        let qc = m.highest_commit_qc().unwrap();
        assert_eq!(
            qc.block_hash,
            block_hash(0xBB),
            "only block B should be committed"
        );
        assert_eq!(qc.round, 1);
        assert_eq!(qc.phase, BftPhase::Commit);

        // Block A from round 0 has PrepareQC but no CommitQC → not finalized.
        // This is correct: Prepare lock without Commit = abandoned.
    }

    #[test]
    fn three_consecutive_rounds_rotate_leaders() {
        let mut m = manager("v0");

        for expected_round in 0..3u64 {
            let action = m.start_round(expected_round);
            match action {
                ManagerAction::NewRound {
                    round, leader_id, ..
                } => {
                    assert_eq!(round, expected_round);
                    let expected_leader = format!("v{}", expected_round % 4);
                    assert_eq!(leader_id, expected_leader);
                }
                other => panic!("expected NewRound, got {other:?}"),
            }
        }
    }
}
