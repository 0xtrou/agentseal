use std::{collections::HashMap, sync::Arc};

use reqwest::Client;
use tokio::sync::RwLock;

#[derive(Clone, Debug)]
pub struct VirtualKey {
    pub id: String,
    pub key_hash: [u8; 32],
    pub key_plaintext: String,
    pub sandbox_id: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub revoked: bool,
}

#[derive(Clone, Debug)]
pub struct ProxyState {
    pub keys: Arc<RwLock<HashMap<String, VirtualKey>>>,
    pub provider_api_key: String,
    pub default_provider: String,
    pub http_client: Client,
}

impl ProxyState {
    pub fn new(provider_api_key: String, default_provider: String) -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            provider_api_key,
            default_provider,
            http_client: Client::new(),
        }
    }

    pub async fn add_key(&self, key: VirtualKey) {
        self.keys.write().await.insert(key.id.clone(), key);
    }

    pub async fn get_key(&self, id: &str) -> Option<VirtualKey> {
        self.keys.read().await.get(id).cloned()
    }

    pub async fn revoke_key(&self, id: &str) -> bool {
        let mut keys = self.keys.write().await;
        if let Some(key) = keys.get_mut(id) {
            key.revoked = true;
            true
        } else {
            false
        }
    }

    pub async fn all_keys(&self) -> Vec<VirtualKey> {
        self.keys.read().await.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{ProxyState, VirtualKey};
    use sha2::{Digest, Sha256};

    fn test_key(id: &str, plaintext: &str) -> VirtualKey {
        let key_hash: [u8; 32] = Sha256::digest(plaintext.as_bytes()).into();
        VirtualKey {
            id: id.to_string(),
            key_hash,
            key_plaintext: plaintext.to_string(),
            sandbox_id: Some("sbx-1".to_string()),
            created_at: 1,
            expires_at: u64::MAX,
            revoked: false,
        }
    }

    #[tokio::test]
    async fn add_key_and_get_key() {
        let state = ProxyState::new("provider-key".to_string(), "openai".to_string());
        let key = test_key("key-1", "as-test-1");
        state.add_key(key.clone()).await;

        let fetched = state.get_key("key-1").await;
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().key_plaintext, key.key_plaintext);
    }

    #[tokio::test]
    async fn revoke_key_marks_key_revoked() {
        let state = ProxyState::new("provider-key".to_string(), "openai".to_string());
        state.add_key(test_key("key-1", "as-test-1")).await;

        assert!(state.revoke_key("key-1").await);
        assert!(state.get_key("key-1").await.unwrap().revoked);
    }

    #[tokio::test]
    async fn revoke_key_returns_false_for_unknown_key() {
        let state = ProxyState::new("provider-key".to_string(), "openai".to_string());
        assert!(!state.revoke_key("missing").await);
    }
}
