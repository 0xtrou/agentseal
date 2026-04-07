use axum::{
    body::Body,
    http::header::{CACHE_CONTROL, CONNECTION, CONTENT_TYPE},
    response::{IntoResponse, Response},
};
use futures::TryStreamExt;

pub async fn stream_response(upstream_response: reqwest::Response) -> Response {
    let stream = upstream_response
        .bytes_stream()
        .map_ok(|chunk| {
            let text = String::from_utf8_lossy(&chunk);
            let mut out = String::new();
            for line in text.lines() {
                if line.trim_start().starts_with("data:") {
                    out.push_str(line);
                    out.push_str("\n\n");
                }
            }
            bytes::Bytes::from(out)
        })
        .map_err(|err| std::io::Error::other(err.to_string()));

    (
        [
            (CONTENT_TYPE, "text/event-stream"),
            (CACHE_CONTROL, "no-cache"),
            (CONNECTION, "keep-alive"),
        ],
        Body::from_stream(stream),
    )
        .into_response()
}
