//! Host authorization and execution stay in the standalone service. This module
//! has no tokens, grants, filesystem paths or private-operation DTOs.
use crate::error::{ApiError, ErrorCode};
use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, Method, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{MethodFilter, on, post},
};
use std::{future::Future, net::SocketAddr, pin::Pin, sync::Arc};

pub struct RequestMetadata {
    pub peer: SocketAddr,
    pub headers: HeaderMap,
    pub content_length: Option<u64>,
}
pub type ResponseFuture = Pin<Box<dyn Future<Output = Result<Response, ApiError>> + Send>>;
pub trait HashHost: Send + Sync + 'static {
    fn hash(&self, metadata: RequestMetadata, body: Body) -> ResponseFuture;
    fn health(&self, metadata: RequestMetadata) -> ResponseFuture;
}
pub fn router(host: Arc<dyn HashHost>) -> Router {
    Router::new()
        .route("/v1/hash", post(hash))
        .route("/health", on(MethodFilter::GET, health))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(middleware::from_fn(target_boundary))
        .with_state(host)
}
fn rejected(status: StatusCode) -> Response {
    let mut response = ApiError::not_applied(ErrorCode::InvalidRequest).into_response();
    *response.status_mut() = status;
    response
}
async fn not_found() -> Response {
    rejected(StatusCode::NOT_FOUND)
}
async fn method_not_allowed() -> Response {
    rejected(StatusCode::METHOD_NOT_ALLOWED)
}
async fn target_boundary(request: Request<Body>, next: Next) -> Response {
    if request.uri().scheme().is_some()
        || request.uri().authority().is_some()
        || !request.uri().path().starts_with('/')
    {
        return rejected(StatusCode::BAD_REQUEST);
    }
    let expected = match request.uri().path() {
        "/v1/hash" => Some((Method::POST, "POST")),
        "/health" => Some((Method::GET, "GET")),
        _ => None,
    };
    if let Some((method, allowed)) = expected
        && request.method() != method
    {
        let mut response = rejected(StatusCode::METHOD_NOT_ALLOWED);
        response.headers_mut().insert(
            axum::http::header::ALLOW,
            axum::http::HeaderValue::from_static(allowed),
        );
        return response;
    }
    next.run(request).await
}
fn metadata(
    peer: SocketAddr,
    request: &Request<Body>,
    operation: &str,
) -> Result<Option<u64>, ApiError> {
    let deny = || ApiError::not_applied(ErrorCode::InvalidRequest);
    // No client-selected operation/key/paths are meaningful on a raw hash route.
    // Reject, rather than normalize or silently ignore nested authority inputs.
    if request.uri().query().is_some()
        || request.headers().contains_key("x-oncl-key")
        || request.headers().contains_key("x-http-method-override")
        || request
            .headers()
            .get("x-oncl-operation")
            .is_some_and(|v| v.as_bytes() != operation.as_bytes())
        || request.headers().get_all("authorization").iter().count() > 1
        || request.headers().get_all("host").iter().count() != 1
        || peer.ip().is_unspecified()
    {
        return Err(deny());
    }
    request
        .headers()
        .get("content-length")
        .map(|value| {
            let text = value.to_str().map_err(|_| deny())?;
            if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
                return Err(deny());
            }
            text.parse::<u64>().map_err(|_| deny())
        })
        .transpose()
}
async fn hash(
    State(host): State<Arc<dyn HashHost>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Result<Response, ApiError> {
    let content_length = metadata(peer, &request, "hash")?;
    let (parts, body) = request.into_parts();
    host.hash(
        RequestMetadata {
            peer,
            headers: parts.headers,
            content_length,
        },
        body,
    )
    .await
}
async fn health(
    State(host): State<Arc<dyn HashHost>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Result<Response, ApiError> {
    let content_length = metadata(peer, &request, "health")?;
    host.health(RequestMetadata {
        peer,
        headers: request.into_parts().0.headers,
        content_length,
    })
    .await
}
