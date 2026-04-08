use std::{collections::HashMap, sync::Arc};

use reqwest::Client;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

#[derive(Clone, Debug)]
pub struct VirtualKey {
    pub id: String,
    pub key_prefix: String,
    pub key_hash: [u8; 32],
    pub sandbox_id: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub revoked: bool,
}

impl VirtualKey {
    pub fn new(
        id: String,
        key: &str,
        sandbox_id: Option<String>,
        created_at: u64,
        expires_at: u64,
    ) -> Self {
        let key_hash: [u8; 32] = Sha256::digest(key.as_bytes()).into();
        let key_prefix = key.chars().take(8).collect();
        Self {
            id,
            key_prefix,
            key_hash,
            sandbox_id,
            created_at,
            expires_at,
            revoked: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProxyState {
    pub keys: Arc<RwLock<HashMap<[u8; 32], VirtualKey>>>,
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
        self.keys.write().await.insert(key.key_hash, key);
    }

    pub async fn get_key(&self, id: &str) -> Option<VirtualKey> {
        self.keys
            .read()
            .await
            .values()
            .find(|key| key.id == id)
            .cloned()
    }

    pub async fn revoke_key(&self, id: &str) -> bool {
        let mut keys = self.keys.write().await;
        if let Some(key) = keys.values_mut().find(|key| key.id == id) {
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
    use sha2::Digest;

    use super::{ProxyState, VirtualKey};

    fn test_key(id: &str, plaintext: &str) -> VirtualKey {
        VirtualKey::new(
            id.to_string(),
            plaintext,
            Some("sbx-1".to_string()),
            1,
            u64::MAX,
        )
    }

    #[tokio::test]
    async fn add_key_and_get_key() {
        let state = ProxyState::new("provider-key".to_string(), "openai".to_string());
        let key = test_key("key-1", "as-test-1");
        state.add_key(key.clone()).await;

        let fetched = state.get_key("key-1").await;
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().key_hash, key.key_hash);
    }

    #[tokio::test]
    async fn revoke_key_marks_key_revoked() {
        let state = ProxyState::new("provider-key".to_string(), "openai".to_string());
        state.add_key(test_key("key-1", "as-test-1")).await;

        assert!(state.revoke_key("key-1").await);
        assert!(state.get_key("key-1").await.unwrap().revoked);
    }

    #[test]
    fn virtual_key_new_sets_prefix_hash_and_metadata() {
        let key = VirtualKey::new(
            "key-1".to_string(),
            "as-1234567890",
            Some("sbx-1".to_string()),
            111,
            222,
        );

        assert_eq!(key.id, "key-1");
        assert_eq!(key.key_prefix, "as-12345");
        assert_eq!(key.sandbox_id.as_deref(), Some("sbx-1"));
        assert_eq!(key.created_at, 111);
        assert_eq!(key.expires_at, 222);
        assert!(!key.revoked);
        let expected_hash: [u8; 32] = sha2::Sha256::digest("as-1234567890".as_bytes()).into();
        assert_eq!(key.key_hash, expected_hash);
    }

    #[test]
    fn proxy_state_new_sets_provider_fields() {
        let state = ProxyState::new("provider-key".to_string(), "anthropic".to_string());

        assert_eq!(state.provider_api_key, "provider-key");
        assert_eq!(state.default_provider, "anthropic");
    }

    #[tokio::test]
    async fn get_key_returns_none_for_missing_id() {
        let state = ProxyState::new("provider-key".to_string(), "openai".to_string());

        assert!(state.get_key("missing").await.is_none());
    }

    #[tokio::test]
    async fn all_keys_returns_inserted_keys() {
        let state = ProxyState::new("provider-key".to_string(), "openai".to_string());
        state.add_key(test_key("key-1", "as-test-1")).await;
        state.add_key(test_key("key-2", "as-test-2")).await;

        let keys = state.all_keys().await;
        let ids: std::collections::HashSet<_> = keys.into_iter().map(|k| k.id).collect();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains("key-1"));
        assert!(ids.contains("key-2"));
    }

    #[tokio::test]
    async fn revoke_key_returns_false_for_unknown_key() {
        let state = ProxyState::new("provider-key".to_string(), "openai".to_string());
        assert!(!state.revoke_key("missing").await);
    }
}
