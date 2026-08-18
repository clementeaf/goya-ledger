use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::types::LexContract;

#[derive(Clone)]
pub struct LexChainStore {
    contracts: Arc<Mutex<HashMap<String, LexContract>>>,
}

impl LexChainStore {
    pub fn new() -> Self {
        Self {
            contracts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn save(&self, contract: LexContract) {
        self.contracts
            .lock()
            .unwrap()
            .insert(contract.id.clone(), contract);
    }

    pub fn get(&self, id: &str) -> Option<LexContract> {
        self.contracts.lock().unwrap().get(id).cloned()
    }

    pub fn list(&self) -> Vec<LexContract> {
        self.contracts.lock().unwrap().values().cloned().collect()
    }
}

impl Default for LexChainStore {
    fn default() -> Self {
        Self::new()
    }
}
