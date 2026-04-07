use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agent_seal_compiler::compile::{Backend, compile_agent};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::sandbox::{SandboxConfig, SandboxProvisioner, copy_into_sandbox, exec_in_sandbox};
use crate::state::{JobState, ServerState};

static NEXT_JOB_SEQ: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Deserialize)]
pub struct CompileRequest {
    pub project_dir: String,
    pub user_fingerprint: String,
    pub sandbox_fingerprint: String,
}

#[derive(Debug, Serialize)]
pub struct CompileResponse {
    pub job_id: String,
    pub status: JobState,
}

#[derive(Debug, Deserialize)]
pub struct DispatchRequest {
    pub job_id: String,
    pub sandbox: DispatchSandbox,
}

#[derive(Debug, Deserialize)]
pub struct DispatchSandbox {
    pub image: String,
    pub timeout_secs: u64,
    pub memory_mb: Option<u64>,
    pub env: Option<Vec<(String, String)>>,
}

#[derive(Debug, Serialize)]
pub struct JobResultResponse {
    pub job_id: String,
    pub status: JobState,
    pub result: Option<agent_seal_core::types::ExecutionResult>,
}

pub fn build_router(state: ServerState) -> Router {
    Router::new()
        .route("/api/v1/compile", post(compile))
        .route("/api/v1/dispatch", post(dispatch))
        .route("/api/v1/jobs/{job_id}", get(get_job))
        .route("/api/v1/jobs/{job_id}/results", get(get_results))
        .route("/health", get(health))
        .with_state(state)
}

async fn compile(
    State(state): State<ServerState>,
    Json(req): Json<CompileRequest>,
) -> impl IntoResponse {
    let _ = (&req.user_fingerprint, &req.sandbox_fingerprint);

    let job_id = new_job_id();
    let created = state
        .create_job(job_id.clone(), Some(req.project_dir.clone()))
        .await;

    let state_for_task = state.clone();
    let project_dir = req.project_dir;
    let compile_output_dir = state.compile_dir.join(&job_id);
    let job_id_for_task = job_id.clone();

    tokio::spawn(async move {
        let _: Result<_, std::convert::Infallible> = state_for_task
            .update_job::<std::convert::Infallible>(&job_id_for_task, |job| {
                job.status = JobState::Compiling;
                job.error = None;
                Ok(())
            })
            .await;

        if let Err(err) = tokio::fs::create_dir_all(&compile_output_dir).await {
            let _: Result<_, std::convert::Infallible> = state_for_task
                .update_job(&job_id_for_task, |job| {
                    job.status = JobState::Failed;
                    job.error = Some(format!("failed to create compile directory: {err}"));
                    Ok(())
                })
                .await;
            return;
        }

        let project_dir_path = PathBuf::from(&project_dir);
        let output_path = tokio::task::spawn_blocking(move || {
            compile_agent(&project_dir_path, &compile_output_dir, Backend::Nuitka)
        })
        .await;

        match output_path {
            Ok(Ok(path)) => {
                let _: Result<_, std::convert::Infallible> = state_for_task
                    .update_job(&job_id_for_task, |job| {
                        job.status = JobState::Ready;
                        job.output_path = Some(path.to_string_lossy().to_string());
                        job.error = None;
                        Ok(())
                    })
                    .await;
            }
            Ok(Err(err)) => {
                let _: Result<_, std::convert::Infallible> = state_for_task
                    .update_job(&job_id_for_task, |job| {
                        job.status = JobState::Failed;
                        job.error = Some(err.to_string());
                        Ok(())
                    })
                    .await;
            }
            Err(join_err) => {
                let _: Result<_, std::convert::Infallible> = state_for_task
                    .update_job(&job_id_for_task, |job| {
                        job.status = JobState::Failed;
                        job.error = Some(format!("compile task join failure: {join_err}"));
                        Ok(())
                    })
                    .await;
            }
        }
    });

    (
        StatusCode::ACCEPTED,
        Json(CompileResponse {
            job_id,
            status: created.status,
        }),
    )
}

async fn get_job(
    State(state): State<ServerState>,
    Path(job_id): Path<String>,
) -> Result<Json<crate::state::JobStatus>, Response> {
    match state.get_job(&job_id).await {
        Some(job) => Ok(Json(job)),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error":"job not found"})),
        )
            .into_response()),
    }
}

async fn dispatch(
    State(state): State<ServerState>,
    Json(req): Json<DispatchRequest>,
) -> Result<(StatusCode, Json<CompileResponse>), Response> {
    let Some(job) = state.get_job(&req.job_id).await else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error":"job not found"})),
        )
            .into_response());
    };

    if job.status != JobState::Ready {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"job is not ready for dispatch"})),
        )
            .into_response());
    }

    let sandbox_cfg = SandboxConfig {
        image: req.sandbox.image,
        env: req.sandbox.env.unwrap_or_default(),
        memory_mb: req.sandbox.memory_mb,
        timeout_secs: req.sandbox.timeout_secs,
    };

    let job_id = req.job_id;
    let job_id_for_task = job_id.clone();
    let state_for_task = state.clone();

    let _: Result<(), std::convert::Infallible> = state
        .update_job(&job_id, |job| {
            job.status = JobState::Dispatched;
            job.error = None;
            Ok(())
        })
        .await;

    tokio::spawn(async move {
        let provisioner = SandboxProvisioner::new();
        let Some(job_snapshot) = state_for_task.get_job(&job_id_for_task).await else {
            return;
        };
        let Some(output_path) = job_snapshot.output_path else {
            let _: Result<_, std::convert::Infallible> = state_for_task
                .update_job::<std::convert::Infallible>(&job_id_for_task, |job| {
                    job.status = JobState::Failed;
                    job.error = Some("job has no output artifact".to_string());
                    Ok(())
                })
                .await;
            return;
        };

        let sandbox = match provisioner.provision(&sandbox_cfg).await {
            Ok(handle) => handle,
            Err(err) => {
                let _: Result<_, std::convert::Infallible> = state_for_task
                    .update_job(&job_id_for_task, |job| {
                        job.status = JobState::Failed;
                        job.error = Some(format!("sandbox provision failed: {err}"));
                        Ok(())
                    })
                    .await;
                return;
            }
        };

        let _: Result<_, std::convert::Infallible> = state_for_task
            .update_job(&job_id_for_task, |job| {
                job.status = JobState::Running;
                job.sandbox_id = Some(sandbox.id.clone());
                Ok(())
            })
            .await;

        let _ = provisioner.collect_fingerprint(&sandbox).await;

        let binary_path = PathBuf::from(&output_path);
        let copy_res =
            copy_into_sandbox(&provisioner, &sandbox, &binary_path, "/tmp/agent-sealed").await;

        if let Err(err) = copy_res {
            let _ = provisioner.destroy(&sandbox).await;
            let _: Result<_, std::convert::Infallible> = state_for_task
                .update_job(&job_id_for_task, |job| {
                    job.status = JobState::Failed;
                    job.error = Some(format!("sandbox copy failed: {err}"));
                    Ok(())
                })
                .await;
            return;
        }

        let exec_result = exec_in_sandbox(
            &provisioner,
            &sandbox,
            "chmod +x /tmp/agent-sealed && /tmp/agent-sealed",
            sandbox_cfg.timeout_secs,
        )
        .await;
        let destroy_result = provisioner.destroy(&sandbox).await;

        match (exec_result, destroy_result) {
            (Ok(result), Ok(())) => {
                let _: Result<_, std::convert::Infallible> = state_for_task
                    .update_job(&job_id_for_task, |job| {
                        job.status = JobState::Completed;
                        job.result = Some(result);
                        job.error = None;
                        Ok(())
                    })
                    .await;
            }
            (Ok(result), Err(err)) => {
                let _: Result<_, std::convert::Infallible> = state_for_task
                    .update_job(&job_id_for_task, |job| {
                        job.status = JobState::Completed;
                        job.result = Some(result);
                        job.error = Some(format!("sandbox destroy failed: {err}"));
                        Ok(())
                    })
                    .await;
            }
            (Err(err), _) => {
                let _: Result<_, std::convert::Infallible> = state_for_task
                    .update_job(&job_id_for_task, |job| {
                        job.status = JobState::Failed;
                        job.error = Some(format!("sandbox exec failed: {err}"));
                        Ok(())
                    })
                    .await;
            }
        }
    });

    Ok((
        StatusCode::ACCEPTED,
        Json(CompileResponse {
            job_id,
            status: JobState::Dispatched,
        }),
    ))
}

async fn get_results(
    State(state): State<ServerState>,
    Path(job_id): Path<String>,
) -> Result<Json<JobResultResponse>, Response> {
    match state.get_job(&job_id).await {
        Some(job) => Ok(Json(JobResultResponse {
            job_id: job.id,
            status: job.status,
            result: job.result,
        })),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error":"job not found"})),
        )
            .into_response()),
    }
}

async fn health(State(state): State<ServerState>) -> impl IntoResponse {
    let jobs_count = state.jobs.read().await.len();
    (
        StatusCode::OK,
        Json(json!({"status":"ok","jobs_count":jobs_count})),
    )
}

fn random_hex_4() -> String {
    let mut bytes = [0_u8; 4];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn new_job_id() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();
    let seq = NEXT_JOB_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("job-{now}-{seq}-{}", random_hex_4())
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use agent_seal_core::types::ExecutionResult;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use serde_json::Value;
    use tower::ServiceExt;

    use crate::{
        create_app,
        state::{JobState, ServerState},
    };

    use super::{build_router, new_job_id, random_hex_4};

    fn test_state() -> ServerState {
        let root = std::env::temp_dir().join("agent-seal-server-tests");
        ServerState::new(root.join("compile"), root.join("output"))
    }

    async fn response_json(response: axum::response::Response) -> Value {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response bytes should be readable");
        serde_json::from_slice(&body).expect("response must be json")
    }

    async fn wait_for_status(state: &ServerState, job_id: &str, expected: JobState) {
        for _ in 0..40 {
            if let Some(job) = state.get_job(job_id).await
                && job.status == expected
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        panic!("job did not reach expected status");
    }

    #[tokio::test]
    async fn compile_returns_accepted_with_job_id() {
        let app = create_app(test_state());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/compile")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"project_dir":"/tmp/demo-agent","user_fingerprint":"abcd","sandbox_fingerprint":"auto"}"#,
                    ))
                    .expect("request must be valid"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let payload = response_json(response).await;
        assert!(payload["job_id"].as_str().is_some());
        assert_eq!(payload["status"], "pending");
    }

    #[tokio::test]
    async fn get_job_returns_job_status() {
        let app = create_app(test_state());

        let create_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/compile")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"project_dir":"/tmp/demo-agent","user_fingerprint":"abcd","sandbox_fingerprint":"auto"}"#,
                    ))
                    .expect("request must be valid"),
            )
            .await
            .expect("compile request should complete");
        let created = response_json(create_response).await;
        let job_id = created["job_id"]
            .as_str()
            .expect("job id string")
            .to_string();

        let get_response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/jobs/{job_id}"))
                    .body(Body::empty())
                    .expect("request must be valid"),
            )
            .await
            .expect("get request should complete");

        assert_eq!(get_response.status(), StatusCode::OK);
        let payload = response_json(get_response).await;
        assert_eq!(payload["id"], job_id);
    }

    #[tokio::test]
    async fn get_job_returns_404_for_missing_id() {
        let app = create_app(test_state());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/jobs/missing")
                    .body(Body::empty())
                    .expect("request must be valid"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn dispatch_non_ready_job_returns_bad_request() {
        let app = create_app(test_state());

        let create_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/compile")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"project_dir":"/tmp/demo-agent","user_fingerprint":"abcd","sandbox_fingerprint":"auto"}"#,
                    ))
                    .expect("request must be valid"),
            )
            .await
            .expect("compile request should complete");
        let created = response_json(create_response).await;
        let job_id = created["job_id"].as_str().expect("job id string");

        let dispatch_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/dispatch")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        "{{\"job_id\":\"{job_id}\",\"sandbox\":{{\"image\":\"python:3.11\",\"timeout_secs\":300}}}}"
                    )))
                    .expect("request must be valid"),
            )
            .await
            .expect("dispatch request should complete");

        assert_eq!(dispatch_response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn build_router_returns_router() {
        let _router = build_router(test_state());
    }

    #[test]
    fn random_hex_4_returns_eight_hex_chars() {
        let hex = random_hex_4();
        assert_eq!(hex.len(), 8);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn new_job_id_has_expected_prefix_and_is_unique() {
        let first = new_job_id();
        let second = new_job_id();

        assert!(first.starts_with("job-"));
        assert!(second.starts_with("job-"));
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn dispatch_missing_job_returns_404() {
        let app = create_app(test_state());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/dispatch")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"job_id":"missing","sandbox":{"image":"python:3.11","timeout_secs":30}}"#,
                    ))
                    .expect("request must be valid"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn dispatch_ready_job_without_output_path_transitions_to_failed() {
        let state = test_state();
        let job = state
            .create_job("job-ready-no-output".to_string(), None)
            .await;
        let _: Result<(), Infallible> = state
            .update_job(&job.id, |job| {
                job.status = JobState::Ready;
                job.output_path = None;
                Ok(())
            })
            .await;
        let app = create_app(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/dispatch")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        "{{\"job_id\":\"{}\",\"sandbox\":{{\"image\":\"python:3.11\",\"timeout_secs\":30}}}}",
                        job.id
                    )))
                    .expect("request must be valid"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::ACCEPTED);

        wait_for_status(&state, &job.id, JobState::Failed).await;
        let updated = state
            .get_job(&job.id)
            .await
            .expect("job should still exist");
        assert_eq!(updated.error.as_deref(), Some("job has no output artifact"));
    }

    #[tokio::test]
    async fn dispatch_ready_job_with_invalid_sandbox_config_fails() {
        let state = test_state();
        let job = state
            .create_job("job-ready-invalid-sandbox".to_string(), None)
            .await;
        let _: Result<(), Infallible> = state
            .update_job(&job.id, |job| {
                job.status = JobState::Ready;
                job.output_path = Some("/tmp/irrelevant".to_string());
                Ok(())
            })
            .await;
        let app = create_app(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/dispatch")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        "{{\"job_id\":\"{}\",\"sandbox\":{{\"image\":\"invalid image\",\"timeout_secs\":30}}}}",
                        job.id
                    )))
                    .expect("request must be valid"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::ACCEPTED);

        wait_for_status(&state, &job.id, JobState::Failed).await;
        let updated = state
            .get_job(&job.id)
            .await
            .expect("job should still exist");
        assert!(
            updated
                .error
                .as_deref()
                .expect("job should include error")
                .contains("sandbox provision failed")
        );
    }

    #[tokio::test]
    async fn get_results_returns_404_for_missing_job() {
        let app = create_app(test_state());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/jobs/missing/results")
                    .body(Body::empty())
                    .expect("request must be valid"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_results_returns_result_payload_when_job_completed() {
        let state = test_state();
        let job = state.create_job("job-with-result".to_string(), None).await;
        let _: Result<(), Infallible> = state
            .update_job(&job.id, |job| {
                job.status = JobState::Completed;
                job.result = Some(ExecutionResult {
                    exit_code: 0,
                    stdout: "ok".to_string(),
                    stderr: String::new(),
                });
                Ok(())
            })
            .await;
        let app = create_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/jobs/{}/results", job.id))
                    .body(Body::empty())
                    .expect("request must be valid"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let payload = response_json(response).await;
        assert_eq!(payload["job_id"], "job-with-result");
        assert_eq!(payload["status"], "completed");
        assert_eq!(payload["result"]["exit_code"], 0);
        assert_eq!(payload["result"]["stdout"], "ok");
    }

    #[tokio::test]
    async fn get_results_returns_null_result_when_job_has_none() {
        let state = test_state();
        let job = state.create_job("job-no-result".to_string(), None).await;
        let _: Result<(), Infallible> = state
            .update_job(&job.id, |job| {
                job.status = JobState::Ready;
                Ok(())
            })
            .await;
        let app = create_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/jobs/{}/results", job.id))
                    .body(Body::empty())
                    .expect("request must be valid"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let payload = response_json(response).await;
        assert_eq!(payload["job_id"], "job-no-result");
        assert_eq!(payload["status"], "ready");
        assert_eq!(payload["result"], serde_json::Value::Null);
    }

    #[tokio::test]
    async fn health_returns_ok_with_jobs_count() {
        let app = create_app(test_state());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("request must be valid"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let payload = response_json(response).await;
        assert_eq!(payload["status"], "ok");
        assert!(payload["jobs_count"].as_u64().is_some());
    }
}
