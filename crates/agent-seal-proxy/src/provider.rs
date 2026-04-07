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
