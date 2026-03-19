use std::sync::Arc;

use axum::extract::Path;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use rust_embed::Embed;

use crate::state::UnifiedState;

#[derive(Embed)]
#[folder = "../../web-ui-unified/"]
struct Assets;

fn serve_asset(path: &str) -> Response {
    match Assets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, mime.as_ref())],
                content.data.to_vec(),
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

pub fn routes() -> Router<Arc<UnifiedState>> {
    Router::new()
        .route("/", get(index_handler))
        .route("/{*path}", get(static_handler))
}

async fn index_handler() -> Response {
    serve_asset("index.html")
}

async fn static_handler(Path(path): Path<String>) -> Response {
    // Don't serve static files for API routes — let them 404 at the API layer
    if path.starts_with("api/") {
        return StatusCode::NOT_FOUND.into_response();
    }
    serve_asset(&path)
}
