pub mod auth;
pub mod provider;
pub mod rate_limit;
pub mod routes;
pub mod state;
pub mod stream;

use std::num::NonZeroU32;

use axum::Router;
use rate_limit::RateLimitLayer;
use routes::{AppState, build_router};
use state::ProxyState;

pub fn create_app(state: ProxyState) -> Router {
    let app_state = AppState {
        proxy: state,
        rate_limit: RateLimitLayer::new(
            NonZeroU32::new(10).expect("non zero"),
            NonZeroU32::new(2).expect("non zero"),
        ),
    };
    build_router(app_state)
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use super::{ProxyState, create_app};

    #[tokio::test]
    async fn create_app_serves_health_route() {
        let app = create_app(ProxyState::new(
            "provider-key".to_string(),
            "openai".to_string(),
        ));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should succeed");

        assert_eq!(response.status(), StatusCode::OK);
    }
}
