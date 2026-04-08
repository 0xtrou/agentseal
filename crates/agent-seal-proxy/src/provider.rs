use std::str::FromStr;

use agent_seal_core::error::SealError;
use axum::{body::Body, http::Response as HttpResponse, response::Response};
use bytes::Bytes;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use crate::{auth::VirtualKeyAuth, state::ProxyState};

#[derive(Clone, Debug)]
pub struct ProviderConfig {
    pub name: String,
    pub base_url: String,
    pub api_key_header: String,
    pub models: Vec<String>,
}

pub async fn proxy_request(
    state: &ProxyState,
    _auth: &VirtualKeyAuth,
    body: Bytes,
    model: &str,
) -> Result<Response, SealError> {
    let provider = provider_for_model(model, &state.default_provider);
    let mut headers = HeaderMap::new();

    match provider.name.as_str() {
        "openai" => {
            headers.insert(
                reqwest::header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {}", state.provider_api_key))
                    .map_err(|err| SealError::InvalidInput(err.to_string()))?,
            );
        }
        "anthropic" => {
            headers.insert(
                HeaderName::from_str("x-api-key")
                    .map_err(|err| SealError::InvalidInput(err.to_string()))?,
                HeaderValue::from_str(&state.provider_api_key)
                    .map_err(|err| SealError::InvalidInput(err.to_string()))?,
            );
            headers.insert(
                HeaderName::from_static("anthropic-version"),
                HeaderValue::from_static("2023-06-01"),
            );
        }
        _ => {
            return Err(SealError::InvalidInput(format!(
                "unsupported provider: {}",
                provider.name
            )));
        }
    }

    headers.insert(
        reqwest::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );

    let upstream = state
        .http_client
        .post(provider_endpoint(&provider.name))
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|err| SealError::Other(anyhow::anyhow!("upstream request failed: {err}")))?;

    let status = upstream.status();
    let upstream_headers = upstream.headers().clone();
    let response_body = upstream.bytes().await.map_err(|err| {
        SealError::Other(anyhow::anyhow!(
            "failed to read upstream response body: {err}"
        ))
    })?;

    let mut builder = HttpResponse::builder().status(status);
    if let Some(content_type) = upstream_headers.get(reqwest::header::CONTENT_TYPE) {
        builder = builder.header(reqwest::header::CONTENT_TYPE, content_type);
    }

    builder
        .body(Body::from(response_body))
        .map_err(|err| SealError::Other(anyhow::anyhow!("failed to build response: {err}")))
}

pub fn provider_for_model(model: &str, default_provider: &str) -> ProviderConfig {
    if model.starts_with("claude") || model.contains("anthropic") {
        ProviderConfig {
            name: "anthropic".to_string(),
            base_url: "https://api.anthropic.com".to_string(),
            api_key_header: "x-api-key".to_string(),
            models: vec![model.to_string()],
        }
    } else if model.starts_with("gpt") || model.starts_with("o") {
        ProviderConfig {
            name: "openai".to_string(),
            base_url: "https://api.openai.com".to_string(),
            api_key_header: "Authorization".to_string(),
            models: vec![model.to_string()],
        }
    } else {
        let name = if default_provider == "anthropic" {
            "anthropic"
        } else {
            "openai"
        };
        ProviderConfig {
            name: name.to_string(),
            base_url: if name == "anthropic" {
                "https://api.anthropic.com".to_string()
            } else {
                "https://api.openai.com".to_string()
            },
            api_key_header: if name == "anthropic" {
                "x-api-key".to_string()
            } else {
                "Authorization".to_string()
            },
            models: vec![model.to_string()],
        }
    }
}

pub fn provider_endpoint(provider_name: &str) -> &'static str {
    match provider_name {
        "anthropic" => "https://api.anthropic.com/v1/messages",
        _ => "https://api.openai.com/v1/chat/completions",
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use reqwest::{Client, Proxy};

    use super::{provider_endpoint, provider_for_model, proxy_request};
    use crate::{auth::VirtualKeyAuth, state::ProxyState};
    use agent_seal_core::error::SealError;

    fn failing_http_client() -> Client {
        Client::builder()
            .proxy(Proxy::all("http://127.0.0.1:1").expect("proxy should build"))
            .build()
            .expect("client should build")
    }

    #[test]
    fn provider_for_model_builds_expected_metadata() {
        let anthropic = provider_for_model("claude-3-5-sonnet", "openai");
        assert_eq!(anthropic.name, "anthropic");
        assert_eq!(anthropic.base_url, "https://api.anthropic.com");
        assert_eq!(anthropic.api_key_header, "x-api-key");
        assert_eq!(anthropic.models, vec!["claude-3-5-sonnet".to_string()]);

        let openai = provider_for_model("gpt-4o-mini", "anthropic");
        assert_eq!(openai.name, "openai");
        assert_eq!(openai.base_url, "https://api.openai.com");
        assert_eq!(openai.api_key_header, "Authorization");
        assert_eq!(openai.models, vec!["gpt-4o-mini".to_string()]);
    }

    #[test]
    fn provider_for_model_falls_back_to_default_provider() {
        assert_eq!(
            provider_for_model("custom-model", "anthropic").name,
            "anthropic"
        );
        assert_eq!(provider_for_model("custom-model", "openai").name, "openai");
        assert_eq!(provider_for_model("custom-model", "unknown").name, "openai");
    }

    #[test]
    fn provider_endpoint_maps_known_and_unknown_providers() {
        assert_eq!(
            provider_endpoint("anthropic"),
            "https://api.anthropic.com/v1/messages"
        );
        assert_eq!(
            provider_endpoint("openai"),
            "https://api.openai.com/v1/chat/completions"
        );
        assert_eq!(
            provider_endpoint("unknown"),
            "https://api.openai.com/v1/chat/completions"
        );
    }

    #[tokio::test]
    async fn proxy_request_rejects_invalid_openai_header_value() {
        let state = ProxyState::new("bad\nkey".to_string(), "openai".to_string());
        let auth = VirtualKeyAuth {
            key_id: "key-1".to_string(),
            sandbox_id: Some("sbx-1".to_string()),
        };

        let err = proxy_request(
            &state,
            &auth,
            Bytes::from_static(br#"{"model":"gpt-4o-mini"}"#),
            "gpt-4o-mini",
        )
        .await
        .expect_err("invalid header value should fail before network call");

        assert!(matches!(err, SealError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn proxy_request_rejects_invalid_anthropic_header_value() {
        let state = ProxyState::new("bad\nkey".to_string(), "anthropic".to_string());
        let auth = VirtualKeyAuth {
            key_id: "key-1".to_string(),
            sandbox_id: Some("sbx-1".to_string()),
        };

        let err = proxy_request(
            &state,
            &auth,
            Bytes::from_static(br#"{"model":"claude-3-haiku"}"#),
            "claude-3-haiku",
        )
        .await
        .expect_err("invalid header value should fail before network call");

        assert!(matches!(err, SealError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn proxy_request_reports_upstream_failures() {
        let mut state = ProxyState::new("provider-key".to_string(), "openai".to_string());
        state.http_client = failing_http_client();
        let auth = VirtualKeyAuth {
            key_id: "key-1".to_string(),
            sandbox_id: Some("sbx-1".to_string()),
        };

        let err = proxy_request(
            &state,
            &auth,
            Bytes::from_static(br#"{"model":"gpt-4o-mini"}"#),
            "gpt-4o-mini",
        )
        .await
        .expect_err("network failure should be reported");

        assert!(err.to_string().contains("upstream request failed"));
    }
}
