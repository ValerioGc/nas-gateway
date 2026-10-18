//! The built interface. A path is a file inside the directory or, without an extension, a route of
//! the interface itself, which is `index.html`'s to draw.

use axum::{
    http::{header, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
};
use std::path::{Component, Path};

const NO_INDEX: &str = "noindex, nofollow, noarchive, nosnippet, noimageindex";

pub async fn serve(root: &Path, method: &Method, path: &str) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }

    let relative = Path::new(path.trim_start_matches('/'));
    if !relative
        .components()
        .all(|part| matches!(part, Component::Normal(_)))
    {
        return StatusCode::NOT_FOUND.into_response();
    }

    let file = root.join(relative);
    let file = if tokio::fs::metadata(&file)
        .await
        .is_ok_and(|found| found.is_file())
    {
        file
    } else if relative.extension().is_none() {
        root.join("index.html")
    } else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let bytes = match tokio::fs::read(&file).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return StatusCode::NOT_FOUND.into_response()
        }
        Err(error) => {
            eprintln!("cannot read {}: {error}", file.display());
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let mut response = bytes.into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(mime(&file)));

    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(if relative.starts_with("assets") {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        }),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );

    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("frame-ancestors 'none'"),
    );
    headers.insert("x-robots-tag", HeaderValue::from_static(NO_INDEX));
    response
}

fn mime(file: &Path) -> &'static str {
    match file
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
    {
        "html" => "text/html; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "webp" => "image/webp",
        "woff2" => "font/woff2",
        "json" | "map" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}
