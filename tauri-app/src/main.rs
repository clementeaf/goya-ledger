#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod key_crypto;

use commands::{
    CommandError, FaucetResult, IdentityInfo, NodeStatus, NotarizeResult, ProposalSummary,
    TransferResult, VoteTally, WalletBalance,
};
use rust_bc::light_client::local_store::LocalIdentityStore;
use rust_bc::light_client::proxy::SeedProxy;
use std::sync::Mutex;

/// App state shared across Tauri commands.
struct AppState {
    store: LocalIdentityStore,
    proxy: SeedProxy,
}

// ── Tauri command wrappers ──
// Each wraps the testable fn from commands.rs with Tauri state extraction.

#[tauri::command]
fn cmd_create_identity(
    state: tauri::State<'_, Mutex<AppState>>,
    algorithm: String,
    password: String,
) -> Result<IdentityInfo, CommandError> {
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    commands::create_identity(&s.store, &algorithm, &password)
}

#[tauri::command]
fn cmd_unlock_identity(
    state: tauri::State<'_, Mutex<AppState>>,
    did: String,
    password: String,
) -> Result<String, CommandError> {
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    commands::unlock_identity(&s.store, &did, &password)
}

#[tauri::command]
fn cmd_list_identities(
    state: tauri::State<'_, Mutex<AppState>>,
) -> Result<Vec<IdentityInfo>, CommandError> {
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    commands::list_identities(&s.store)
}

#[tauri::command]
fn cmd_hash_document(data: Vec<u8>) -> String {
    commands::hash_document(&data)
}

#[tauri::command]
async fn cmd_notarize(
    state: tauri::State<'_, Mutex<AppState>>,
    did: String,
    password: String,
    file_name: String,
    file_bytes: Vec<u8>,
) -> Result<NotarizeResult, CommandError> {
    let (proxy, store_path) = {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        (s.proxy.clone(), s.store.path().to_path_buf())
    };
    let store = LocalIdentityStore::open(store_path);
    commands::notarize_document(&proxy, &store, &did, &password, &file_name, &file_bytes).await
}

#[tauri::command]
async fn cmd_verify_notarization(
    state: tauri::State<'_, Mutex<AppState>>,
    hash: String,
) -> Result<serde_json::Value, CommandError> {
    let proxy = {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        s.proxy.clone()
    };
    commands::verify_notarization(&proxy, &hash).await
}

#[tauri::command]
async fn cmd_node_status(
    state: tauri::State<'_, Mutex<AppState>>,
) -> Result<NodeStatus, CommandError> {
    let (proxy, store_path) = {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        (s.proxy.clone(), s.store.path().to_path_buf())
    };
    let store = LocalIdentityStore::open(store_path);
    commands::get_node_status(&proxy, &store).await
}

#[tauri::command]
async fn cmd_get_balance(
    state: tauri::State<'_, Mutex<AppState>>,
    address: String,
) -> Result<WalletBalance, CommandError> {
    let proxy = {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        s.proxy.clone()
    };
    commands::get_balance(&proxy, &address).await
}

#[tauri::command]
async fn cmd_request_faucet(
    state: tauri::State<'_, Mutex<AppState>>,
    recipient: String,
    amount: u64,
) -> Result<FaucetResult, CommandError> {
    let proxy = {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        s.proxy.clone()
    };
    commands::request_faucet(&proxy, &recipient, amount).await
}

#[tauri::command]
async fn cmd_send_transfer(
    state: tauri::State<'_, Mutex<AppState>>,
    from_did: String,
    password: String,
    to_address: String,
    amount: u64,
) -> Result<TransferResult, CommandError> {
    let (proxy, store_path) = {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        (s.proxy.clone(), s.store.path().to_path_buf())
    };
    let store = LocalIdentityStore::open(store_path);
    commands::send_transfer(&proxy, &store, &from_did, &password, &to_address, amount).await
}

#[tauri::command]
async fn cmd_get_transactions(
    state: tauri::State<'_, Mutex<AppState>>,
    address: String,
) -> Result<Vec<serde_json::Value>, CommandError> {
    let proxy = {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        s.proxy.clone()
    };
    commands::get_transactions(&proxy, &address).await
}

#[tauri::command]
async fn cmd_list_proposals(
    state: tauri::State<'_, Mutex<AppState>>,
) -> Result<Vec<ProposalSummary>, CommandError> {
    let proxy = {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        s.proxy.clone()
    };
    commands::list_proposals(&proxy).await
}

#[tauri::command]
async fn cmd_create_proposal(
    state: tauri::State<'_, Mutex<AppState>>,
    proposer: String,
    title: String,
    description: String,
    deposit: u64,
) -> Result<serde_json::Value, CommandError> {
    let proxy = {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        s.proxy.clone()
    };
    commands::create_proposal(&proxy, &proposer, &title, &description, deposit).await
}

#[tauri::command]
async fn cmd_cast_vote(
    state: tauri::State<'_, Mutex<AppState>>,
    did: String,
    password: String,
    proposal_id: u64,
    option: String,
) -> Result<VoteTally, CommandError> {
    let (proxy, store_path) = {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        (s.proxy.clone(), s.store.path().to_path_buf())
    };
    let store = LocalIdentityStore::open(store_path);
    commands::cast_vote(&proxy, &store, &did, &password, proposal_id, &option).await
}

#[tauri::command]
async fn cmd_get_tally(
    state: tauri::State<'_, Mutex<AppState>>,
    proposal_id: u64,
) -> Result<VoteTally, CommandError> {
    let proxy = {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        s.proxy.clone()
    };
    commands::get_tally(&proxy, proposal_id).await
}

fn main() {
    let seed_url =
        std::env::var("SEED_NODE_URL").unwrap_or_else(|_| "https://goya-node.fly.dev".to_string());

    let store = LocalIdentityStore::from_env();
    let proxy = SeedProxy::new(seed_url);

    let app_state = Mutex::new(AppState { store, proxy });

    tauri::Builder::default()
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            cmd_create_identity,
            cmd_unlock_identity,
            cmd_list_identities,
            cmd_hash_document,
            cmd_notarize,
            cmd_verify_notarization,
            cmd_node_status,
            cmd_get_balance,
            cmd_request_faucet,
            cmd_send_transfer,
            cmd_get_transactions,
            cmd_list_proposals,
            cmd_create_proposal,
            cmd_cast_vote,
            cmd_get_tally,
        ])
        .run(tauri::generate_context!())
        .expect("failed to run GOYA-ledger app");
}
