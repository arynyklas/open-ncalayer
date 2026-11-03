//! Exact immutable authority on the original context, including mandatory validation.
use super::*;
use oncl_pki::http::{HttpMethod, HttpRequest, PkiMethod, ProtocolTarget};
#[derive(Clone, Debug)]
pub(crate) struct InvocationPkiAuthority {
    pub(super) grant: Arc<[PluginPermission]>,
    pub(super) host: Arc<[PluginPermission]>,
    pub(super) identity: usize,
    pub(super) import: Import,
    pub(super) budget: InvocationHttpBudget,
}
fn canonical(url: &str) -> Option<oncl_plugin::Url> {
    let parsed = oncl_plugin::Url::parse(url).ok()?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    // Do not turn dot segments, encoded separators, port aliases or fragments
    // into authority. The sole syntactic convenience is a missing root slash.
    if parsed.as_str() != url
        && !(parsed.path() == "/"
            && parsed.query().is_none()
            && parsed.as_str().strip_suffix('/') == Some(url))
    {
        return None;
    }
    Some(parsed)
}
impl InvocationPkiAuthority {
    fn permits(&self, method: Option<HttpMethod>, url: &str) -> bool {
        let Some(url) = canonical(url) else {
            return false;
        };
        let identity = &self.grant[self.identity];
        let matches = |p: &&PluginPermission| {
            p.plugin_id == identity.plugin_id
                && p.operation == identity.operation
                && p.caller == identity.caller
                && p.permits(self.import, None)
        };
        let endpoint = |p: &PluginPermission| {
            p.pki_endpoints
                .iter()
                .any(|e| method.is_none_or(|m| m == e.method) && e.url == url.as_str())
        };
        self.grant.iter().filter(matches).any(endpoint)
            && self.host.iter().filter(matches).any(endpoint)
    }
    fn denied(&self) -> OperationError {
        self.budget.reject()
    }
    pub(crate) fn check(
        &self,
        request: &HttpRequest<'_>,
        target: Option<&ProtocolTarget<'_>>,
    ) -> Result<(), OperationError> {
        if self.permits(Some(request.method), request.url) {
            return Ok(());
        }
        if request.method == HttpMethod::Get
            && let Some(base) = target.and_then(|t| t.generated_get_base(request))
            && self.permits(Some(HttpMethod::Get), base)
        {
            return Ok(());
        }
        Err(self.denied())
    }
}
impl oncl_plugin::headless::PkiAuthority for InvocationPkiAuthority {
    fn authorize_url(&self, url: &str) -> abi::HostResult<()> {
        if self.permits(None, url) {
            Ok(())
        } else {
            let _ = self.denied();
            Err(abi::HostError::new(
                abi::ErrorCode::Denied,
                "PKI target not authorized",
            ))
        }
    }
    fn authorize_request(
        &self,
        request: &HttpRequest<'_>,
        target: Option<&ProtocolTarget<'_>>,
    ) -> abi::HostResult<()> {
        self.check(request, target)
            .map_err(|_| abi::HostError::new(abi::ErrorCode::Denied, "PKI request not authorized"))
    }
    fn authorize_tsa(&self, spec: &oncl_pki::tsp::TsaSpec) -> abi::HostResult<()> {
        let allowed = match &spec.method {
            PkiMethod::Post { .. } => self.permits(Some(HttpMethod::Post), &spec.url),
            PkiMethod::Get | PkiMethod::GetUrlEncoded => {
                self.permits(Some(HttpMethod::Get), &spec.url)
            }
            PkiMethod::GetUnder(_) => {
                self.permits(Some(HttpMethod::Get), &spec.url)
                    && self.permits(Some(HttpMethod::Post), &spec.url)
            }
            PkiMethod::PostWithPath => false,
        };
        if allowed {
            Ok(())
        } else {
            let _ = self.denied();
            Err(abi::HostError::new(
                abi::ErrorCode::Denied,
                "TSA binding not authorized",
            ))
        }
    }
}
pub(super) struct ActivePkiScope<'a> {
    pub(super) ctx: &'a mut OperationContext,
    previous: Option<InvocationPkiAuthority>,
}
impl<'a> ActivePkiScope<'a> {
    pub(super) fn new(ctx: &'a mut OperationContext, authority: InvocationPkiAuthority) -> Self {
        let previous = ctx.plugin_pki.replace(authority);
        Self { ctx, previous }
    }
}
impl Drop for ActivePkiScope<'_> {
    fn drop(&mut self) {
        self.ctx.plugin_pki = self.previous.take();
    }
}
