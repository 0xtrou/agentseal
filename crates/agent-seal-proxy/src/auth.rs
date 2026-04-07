use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::state::{ProxyState, VirtualKey};

#[derive(Clone, Debug)]
pub struct VirtualKeyAuth {
    pub key_id: String,
    pub sandbox_id: Option<String>,
}

impl<S> FromRequestParts<S> for VirtualKeyAuth
where
    S: Send + Sync,
    ProxyState: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = ProxyState::from_ref(state);
        let header_value = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();

        let token = header_value
            .strip_prefix("Bearer ")
            .map(str::trim)
            .unwrap_or_default();

        if token.is_empty() {
            return Err(invalid_key_response());
        }

        let candidate_hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let now = unix_ts_secs();

        let keys = state.keys.read().await;
        let matched: Option<VirtualKey> = keys
            .values()
            .find(|key| key.key_hash == candidate_hash)
            .cloned();

        match matched {
            Some(key) if !key.revoked && key.expires_at > now => Ok(VirtualKeyAuth {
                key_id: key.id,
                sandbox_id: key.sandbox_id,
            }),
            _ => Err(invalid_key_response()),
        }
    }
}

fn unix_ts_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

fn invalid_key_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(json!({"error": "invalid or expired key"})),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use crate::{
        create_app,
        state::{ProxyState, VirtualKey},
    };
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;

    fn build_key(id: &str, plaintext: &str, expires_at: u64, revoked: bool) -> VirtualKey {
        let key_hash: [u8; 32] = Sha256::digest(plaintext.as_bytes()).into();
        VirtualKey {
            id: id.to_string(),
            key_hash,
            key_plaintext: plaintext.to_string(),
            sandbox_id: Some("sbx-1".to_string()),
            created_at: 1,
            expires_at,
            revoked,
        }
    }

    #[tokio::test]
    async fn valid_key_passes() {
        let state = ProxyState::new("provider-key".to_string(), "openai".to_string());
        state
            .add_key(build_key("key-1", "as-valid", u64::MAX, false))
            .await;
        let app = create_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/_test/authenticated")
                    .method("GET")
                    .header("authorization", "Bearer as-valid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn invalid_key_returns_401() {
        let app = create_app(ProxyState::new(
            "provider-key".to_string(),
            "openai".to_string(),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/chat/completions")
                    .method("POST")
                    .header("authorization", "Bearer as-invalid")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn expired_key_returns_401() {
        let state = ProxyState::new("provider-key".to_string(), "openai".to_string());
        state
            .add_key(build_key("key-1", "as-expired", 0, false))
            .await;
        let app = create_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/chat/completions")
                    .method("POST")
                    .header("authorization", "Bearer as-expired")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn revoked_key_returns_401() {
        let state = ProxyState::new("provider-key".to_string(), "openai".to_string());
        state
            .add_key(build_key("key-1", "as-revoked", u64::MAX, true))
            .await;
        let app = create_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/chat/completions")
                    .method("POST")
                    .header("authorization", "Bearer as-revoked")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
