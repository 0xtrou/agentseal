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
