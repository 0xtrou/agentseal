pub mod routes;
#[path = "sandbox.rs"]
pub mod sandbox;
pub mod state;

use axum::Router;
use routes::build_router;
use state::ServerState;

pub fn create_app(state: ServerState) -> Router {
    build_router(state)
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use super::{ServerState, create_app};

    #[tokio::test]
    async fn create_app_serves_health_route() {
        let root = std::env::temp_dir().join("snapfzz-seal-server-lib-tests");
        let app = create_app(ServerState::new(root.join("compile"), root.join("output")));

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
