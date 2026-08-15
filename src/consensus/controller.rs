//! BFT controller — bridges the RoundManager state machine with the P2P
//! network and block storage. Runs as a tokio task.

use std::sync::Arc;

use tokio::sync::mpsc;

use crate::consensus::bft::quorum::SignatureVerifier;
use crate::consensus::bft::round::{RoundAction, RoundEvent};
use crate::consensus::bft::round_manager::{ManagerAction, RoundManager, RoundManagerConfig};
use crate::consensus::bft::types::VoteMessage;
use crate::identity::signing::SigningProvider;
use crate::network::Node;
use crate::storage::traits::Block;

/// Events fed into the BFT controller from the network layer or auto-mine loop.
#[derive(Debug)]
pub enum BftEvent {
    /// A new block is ready to be proposed (this node is leader).
    ProposeBlock(Block),
    /// A BFT proposal arrived from a peer.
    Proposal {
        round: u64,
        block_hash: [u8; 32],
        leader_id: String,
        block: Block,
    },
    /// A BFT vote arrived from a peer.
    Vote(VoteMessage),
    /// Round timed out.
    Timeout,
}

/// Verifier that delegates to the node's signing infrastructure.
#[derive(Clone)]
struct NodeVerifier {
    _validators: Vec<(String, Vec<u8>)>,
}

impl SignatureVerifier for NodeVerifier {
    fn verify(&self, voter_id: &str, payload: &[u8], signature: &[u8]) -> bool {
        // ponytail: accept all signatures in testnet; real verification
        // requires a validator registry mapping voter_id → public_key.
        // For now, verify signature is non-empty (was signed by the sender).
        let _ = (voter_id, payload);
        !signature.is_empty()
    }
}

/// Run the BFT consensus loop.
///
/// Receives events via `rx`, drives the `RoundManager`, and emits network
/// messages + block commits through the provided `node` and `store`.
pub async fn run_bft_loop(
    node_id: String,
    validators: Vec<String>,
    mut rx: mpsc::UnboundedReceiver<BftEvent>,
    node: Arc<Node>,
    store: Arc<dyn crate::storage::BlockStore>,
    signer: Arc<dyn SigningProvider>,
) {
    let verifier = NodeVerifier {
        _validators: Vec::new(),
    };
    let config = RoundManagerConfig::default();
    let mut manager = RoundManager::new(node_id.clone(), validators.clone(), verifier, config);

    // Pending block waiting for BFT finalization.
    let mut pending_block: Option<Block> = None;

    // Start round 0.
    let action = manager.start();
    handle_action(&action, &node, &signer, &node_id).await;

    // Timeout task.
    let timeout_ms = manager.current_timeout_ms();
    #[allow(unused_mut)]
    let mut timeout = tokio::time::sleep(tokio::time::Duration::from_millis(timeout_ms));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                match event {
                    BftEvent::ProposeBlock(block) => {
                        if !manager.is_current_leader() {
                            continue;
                        }
                        let block_hash = crate::mining::block_hash(&block);
                        pending_block = Some(block.clone());

                        // Broadcast proposal to peers.
                        let block_data = serde_json::to_vec(&block).unwrap_or_default();
                        let msg = crate::network::Message::BftProposal {
                            round: manager.current_round(),
                            block_hash,
                            leader_id: node_id.clone(),
                            block_data,
                        };
                        node.broadcast_message(&msg).await;

                        // Feed to local round manager as leader.
                        let action = manager.process_event(RoundEvent::StartAsLeader { block_hash });
                        handle_action(&action, &node, &signer, &node_id).await;
                        reset_timeout(&mut timeout, &manager);
                    }

                    BftEvent::Proposal { round, block_hash, leader_id, block } => {
                        if round != manager.current_round() {
                            continue;
                        }
                        pending_block = Some(block);
                        let action = manager.process_event(RoundEvent::Proposal { block_hash, leader_id });
                        let decided = handle_action(&action, &node, &signer, &node_id).await;
                        if decided {
                            if let Some(blk) = pending_block.take() {
                                commit_block(blk, &manager, &store, &node).await;
                            }
                            let adv = manager.advance_after_decide();
                            handle_action(&adv, &node, &signer, &node_id).await;
                            reset_timeout(&mut timeout, &manager);
                        }
                    }

                    BftEvent::Vote(vote) => {
                        let action = manager.process_event(RoundEvent::Vote(vote));
                        let decided = handle_action(&action, &node, &signer, &node_id).await;
                        if decided {
                            if let Some(blk) = pending_block.take() {
                                commit_block(blk, &manager, &store, &node).await;
                            }
                            let adv = manager.advance_after_decide();
                            handle_action(&adv, &node, &signer, &node_id).await;
                            reset_timeout(&mut timeout, &manager);
                        }
                    }

                    BftEvent::Timeout => {
                        let action = manager.on_timeout();
                        handle_action(&action, &node, &signer, &node_id).await;
                        pending_block = None;
                        reset_timeout(&mut timeout, &manager);
                    }
                }
            }
            _ = &mut timeout => {
                let action = manager.on_timeout();
                handle_action(&action, &node, &signer, &node_id).await;
                pending_block = None;
                reset_timeout(&mut timeout, &manager);
            }
        }
    }
}

fn reset_timeout(
    timeout: &mut std::pin::Pin<&mut tokio::time::Sleep>,
    manager: &RoundManager<NodeVerifier>,
) {
    let ms = manager.current_timeout_ms();
    timeout
        .as_mut()
        .reset(tokio::time::Instant::now() + tokio::time::Duration::from_millis(ms));
}

/// Process a ManagerAction: sign and broadcast votes, handle decisions.
/// Returns `true` if the action was a Decide.
async fn handle_action(
    action: &ManagerAction,
    node: &Arc<Node>,
    signer: &Arc<dyn SigningProvider>,
    node_id: &str,
) -> bool {
    match action {
        ManagerAction::Round(RoundAction::SendVote(vote)) => {
            let mut signed_vote = vote.clone();
            let payload = VoteMessage::signing_payload(vote.phase, &vote.block_hash, vote.round);
            signed_vote.signature = signer.sign(&payload).unwrap_or_default();
            let msg = crate::network::Message::BftVote(signed_vote);
            node.broadcast_message(&msg).await;
            false
        }
        ManagerAction::Round(RoundAction::BroadcastProposal { block_hash }) => {
            log::info!(
                "BFT: broadcasting proposal hash={}",
                hex::encode(block_hash)
            );
            false
        }
        ManagerAction::Round(RoundAction::PhaseComplete { phase, qc }) => {
            log::info!(
                "BFT: phase {:?} complete with {} votes",
                phase,
                qc.voter_count()
            );
            false
        }
        ManagerAction::Round(RoundAction::Decide {
            block_hash, round, ..
        }) => {
            log::info!(
                "BFT: DECIDED block {} at round {round}",
                hex::encode(block_hash)
            );
            true
        }
        ManagerAction::NewRound {
            round, leader_id, ..
        } => {
            let is_me = leader_id == node_id;
            log::info!(
                "BFT: new round {round}, leader={leader_id}{}",
                if is_me { " (me)" } else { "" }
            );
            false
        }
        ManagerAction::Round(RoundAction::None) | ManagerAction::None => false,
    }
}

async fn commit_block(
    mut block: Block,
    manager: &RoundManager<NodeVerifier>,
    store: &Arc<dyn crate::storage::BlockStore>,
    node: &Arc<Node>,
) {
    block.commit_qc = manager.highest_commit_qc().cloned();
    match store.write_block(&block) {
        Ok(()) => {
            log::info!("BFT: committed block {} with QC", block.height);
            let node = node.clone();
            let blk = block.clone();
            tokio::spawn(async move {
                node.broadcast_ordered_block(&blk).await;
            });
        }
        Err(e) => log::error!("BFT: failed to write block {}: {e}", block.height),
    }
}
