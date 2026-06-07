//! SPA serving. Behind the `embed-ui` cargo feature: with it on (release), `web/dist/` is compiled
//! into the binary via `rust-embed` (single-binary deploy); with it off (default / CI), no `dist`
//! is needed — a stub explains how to build it. Either way the router's fallback handler serves it.
//!
//! In dev, the SPA is NOT served here at all — Vite serves it on `:5273` and proxies `/api` to the
//! console; this module only matters for the embedded release build.

#[cfg(feature = "embed-ui")]
mod embedded {
    use axum::http::{header, StatusCode, Uri};
    use axum::response::{IntoResponse, Response};
    use rust_embed::RustEmbed;

    #[derive(RustEmbed)]
    #[folder = "../../web/dist/"]
    struct Assets;

    /// Serve an embedded asset by path; unknown non-API paths fall back to `index.html` (SPA
    /// client-side routing). Unknown `/api/*` paths stay a real `404` (not the SPA shell).
    pub async fn serve(uri: Uri) -> Response {
        if uri.path().starts_with("/api/") {
            return (StatusCode::NOT_FOUND, "not found").into_response();
        }
        let path = uri.path().trim_start_matches('/');
        let lookup = if path.is_empty() { "index.html" } else { path };
        if let Some(file) = Assets::get(lookup) {
            let mime = file.metadata.mimetype().to_string();
            return ([(header::CONTENT_TYPE, mime)], file.data.into_owned()).into_response();
        }
        if let Some(index) = Assets::get("index.html") {
            return (
                [(header::CONTENT_TYPE, "text/html".to_string())],
                index.data.into_owned(),
            )
                .into_response();
        }
        (StatusCode::NOT_FOUND, "not found").into_response()
    }
}

#[cfg(not(feature = "embed-ui"))]
mod stub {
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};

    /// UI not embedded (default build). Dev uses the Vite server; the release embeds via
    /// `--features embed-ui` after `pnpm --dir web build`.
    pub async fn serve() -> Response {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "vault-console UI not embedded — run `pnpm --dir web build` and build with --features embed-ui (dev: use the Vite server on :5273)",
        )
            .into_response()
    }
}

#[cfg(feature = "embed-ui")]
pub use embedded::serve as fallback;
#[cfg(not(feature = "embed-ui"))]
pub use stub::serve as fallback;
