use std::sync::Arc;

use crate::storage::traits::BlockStore;

use super::types::LexContract;

#[derive(Clone)]
pub struct LexChainStore {
    backend: Arc<dyn BlockStore>,
}

impl LexChainStore {
    pub fn new() -> Self {
        Self {
            backend: Arc::new(crate::storage::MemoryStore::new()),
        }
    }

    pub fn with_backend(backend: Arc<dyn BlockStore>) -> Self {
        Self { backend }
    }

    pub fn save(&self, contract: LexContract) {
        let _ = self.backend.write_lexcontract(&contract);
    }

    pub fn get(&self, id: &str) -> Option<LexContract> {
        self.backend.read_lexcontract(id).ok()
    }

    pub fn list(&self) -> Vec<LexContract> {
        self.backend.list_lexcontracts().unwrap_or_default()
    }

    pub fn backend(&self) -> &dyn BlockStore {
        &*self.backend
    }
}

impl Default for LexChainStore {
    fn default() -> Self {
        Self::new()
    }
}
