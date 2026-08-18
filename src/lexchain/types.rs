use crate::signature::{BiometricEvidence, SignatureLevel, SignedEnvelope};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartyDefinition {
    pub role: String,
    pub did: String,
    pub signature_level: SignatureLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractDefinition {
    #[serde(rename = "type")]
    pub contract_type: String,
    pub parties: Vec<PartyDefinition>,
    pub payload: serde_json::Value,
    #[serde(default)]
    pub require_notarization: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractState {
    PendingSignatures,
    FullySigned,
    Notarized,
    Archived,
}

impl std::fmt::Display for ContractState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PendingSignatures => write!(f, "pending_signatures"),
            Self::FullySigned => write!(f, "fully_signed"),
            Self::Notarized => write!(f, "notarized"),
            Self::Archived => write!(f, "archived"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartyState {
    pub role: String,
    pub did: String,
    pub signature_level: SignatureLevel,
    pub signed: bool,
    pub envelope: Option<SignedEnvelope>,
}

impl PartyState {
    pub fn from_definition(def: &PartyDefinition) -> Self {
        Self {
            role: def.role.clone(),
            did: def.did.clone(),
            signature_level: def.signature_level,
            signed: false,
            envelope: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LexContract {
    pub id: String,
    pub definition: ContractDefinition,
    pub state: ContractState,
    pub parties: Vec<PartyState>,
    pub created_at: u64,
    pub content_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tsa_token: Option<crate::tsa::TimeStampToken>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_height: Option<u64>,
}

impl LexContract {
    pub fn all_signed(&self) -> bool {
        self.parties.iter().all(|p| p.signed)
    }

    pub fn party_by_did(&self, did: &str) -> Option<&PartyState> {
        self.parties.iter().find(|p| p.did == did)
    }

    pub fn party_by_did_mut(&mut self, did: &str) -> Option<&mut PartyState> {
        self.parties.iter_mut().find(|p| p.did == did)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    pub did: String,
    pub signature: String,
    pub public_key: String,
    #[serde(default)]
    pub biometric_evidence: Vec<BiometricEvidence>,
}
