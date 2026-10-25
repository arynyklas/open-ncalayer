//! Request handling shared by the WebSocket server and the browser extension bridge.

use std::io;
use std::sync::Arc;

use oncl_protocol::{AddInfo, Registry, Route, module_not_found};
use tracing::debug;

/// The reply to a request, or `None` to drop the connection (the request is not a JSON
/// object). The heartbeat is echoed.
pub(crate) fn dispatch(registry: &Registry, text: &str, add_info: &AddInfo) -> Option<String> {
    match registry.route(text) {
        Route::Heartbeat => Some(text.to_owned()),
        Route::Module(module) => Some(module.process(text, add_info)),
        Route::NotFound => Some(module_not_found()),
        Route::InvalidJson => None,
    }
}

/// [`dispatch`] on the blocking pool: routing parses the whole request (possibly tens of
/// megabytes) and a module call may wait for a dialog, so neither may hold up the runtime.
///
/// # Errors
///
/// The module call panicked.
pub(crate) async fn process<T>(
    registry: &Arc<Registry>,
    text: T,
    add_info: &AddInfo,
) -> io::Result<Option<String>>
where
    T: AsRef<str> + Send + 'static,
{
    let registry = Arc::clone(registry);
    let add_info = add_info.clone();
    let len = text.as_ref().len();
    let answer = tokio::task::spawn_blocking(move || dispatch(&registry, text.as_ref(), &add_info))
        .await
        .map_err(io::Error::other)?;
    if let Some(reply) = &answer {
        debug!(
            request_len = len,
            reply_len = reply.len(),
            "request answered"
        );
    }
    Ok(answer)
}
