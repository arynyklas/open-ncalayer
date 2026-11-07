//! The key choice of the manual window (design `manual-plugins.md` 3.5): the user already
//! bound ONE key in the host window, so `keys_select`/`keys_choose`/`keys_flow_*` have
//! nothing to ask. They evaluate the plugin's filter against that key's certificate with
//! the functions of `oncl-flows` the dialogs use, and answer for that single key or for
//! none. The secret and the storage path are never part of [`BoundKey`]; nothing here
//! renders text, so a pure-data [`PluginInteraction`] needs no UI.

use crate::caps::{filter_more, key_filter};
use oncl_flows::FilterMore as BasicsMore;
/// Remembered OCSP answers of a key choice: what [`BoundInteraction`] shares between calls.
pub use oncl_flows::OcspCache;
use oncl_flows::{Availability, KeyFilter, availabilities};
use oncl_pdk::abi::{
    Bytes, ChooseArgs, Chosen, ErrorCode, FlowArgs, FlowChecks, FlowKey, FlowOpened, FlowOutcome,
    HostError, HostResult, Import, MAX_FLOWS, PickArgs, SelectArgs, TerminalsArgs, TokenScan,
};
use oncl_pki::cert::Certificate;
use oncl_pki::http::HttpTransport;
use oncl_pki::info::{KncaCertType, cert_info, kcert_types};
use std::sync::Arc;
use time::OffsetDateTime;

/// The key the user bound in the host window, as far as a plugin may know it: an opaque
/// handle of the host's own key table, the alias and the certificate. Never the secret,
/// never where the key store lives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundKey {
    /// The handle the plugin signs with; it names this key in the host's table.
    pub handle: u32,
    /// The key's alias in its store.
    pub alias: String,
    /// The certificate, DER.
    pub certificate: Vec<u8>,
}

/// What the manual window answers to a plugin's key choice. Pure data suffices: no UI.
pub trait PluginInteraction {
    /// The one key bound in the host window.
    fn bound_key(&self) -> &BoundKey;
    /// The clock the filter's validity and path checks use.
    fn now(&self) -> OffsetDateTime;
    /// The transport of the filter's OCSP check.
    fn http(&self) -> &Arc<dyn HttpTransport>;
    /// Remembered OCSP answers.
    fn ocsp_cache(&self) -> &Arc<OcspCache>;
}

/// A [`PluginInteraction`] made of plain data.
pub struct BoundInteraction {
    pub key: BoundKey,
    pub now: OffsetDateTime,
    pub http: Arc<dyn HttpTransport>,
    pub ocsp_cache: Arc<OcspCache>,
}
impl PluginInteraction for BoundInteraction {
    fn bound_key(&self) -> &BoundKey {
        &self.key
    }
    fn now(&self) -> OffsetDateTime {
        self.now
    }
    fn http(&self) -> &Arc<dyn HttpTransport> {
        &self.http
    }
    fn ocsp_cache(&self) -> &Arc<OcspCache> {
        &self.ocsp_cache
    }
}

/// Per-call answers of the manual window.
pub(crate) struct Manual<'a> {
    interaction: &'a dyn PluginInteraction,
    /// `keys_flow_open`s of the call: whether the bound key matched.
    flows: Vec<bool>,
    /// The evaluations of the call so far. The bound key and the clock are fixed within a
    /// call, so the result is a pure function of the filter: asked twice, answered once.
    evaluated: Vec<(Option<KeyFilter>, Option<Vec<KncaCertType>>, bool)>,
}

/// At most this many DIFFERENT filters are evaluated in a call (each may cost an OCSP
/// request of up to six seconds); the same filter again is answered from memory.
pub const MAX_EVALUATIONS: usize = 16;

/// What [`Manual::answer`] did with an import.
pub(crate) enum Answer {
    /// The encoded result.
    Done(Vec<u8>),
    /// Not a key choice: the backend or the refusal rules decide.
    Other,
    /// A trap the manual window never lets through.
    Refused,
}

impl<'a> Manual<'a> {
    pub(crate) fn new(interaction: &'a dyn PluginInteraction) -> Self {
        Self {
            interaction,
            flows: Vec::new(),
            evaluated: Vec::new(),
        }
    }

    pub(crate) fn answer(&mut self, import: Import, args: &[u8]) -> Answer {
        use crate::host::run;
        Answer::Done(match import {
            Import::KeysChoose => run(args, |a: ChooseArgs| {
                let filter = key_filter(a.filter, BasicsMore::default())?;
                self.choose(&filter)
            }),
            Import::KeysSelect => run(args, |a: SelectArgs| {
                let filter = key_filter(a.filter, filter_more(a.more)?)?;
                self.choose(&filter)
            }),
            Import::KeysFlowOpen => run(args, |a: FlowArgs| self.flow_open(a)),
            Import::KeysFlowPick => run(args, |a: PickArgs| self.flow_pick(a)),
            Import::KeysTerminals => run(args, |_: TerminalsArgs| Ok(Vec::<String>::new())),
            Import::TokensScan => run(args, |()| {
                Ok(TokenScan {
                    enabled: false,
                    present: Vec::new(),
                    any_card: false,
                })
            }),
            // The reply buffer's release: headless Core denies it, which would trap every
            // port that links it; here it is harmless and allowed.
            Import::ReplyDrop => run(args, |()| Ok(())),
            // `PermissionDenied` of headless Core: a trap, so the plugin cannot tell.
            Import::KeysOpen => return Answer::Refused,
            _ => return Answer::Other,
        })
    }

    fn matches(
        &mut self,
        filter: Option<&KeyFilter>,
        kinds: Option<&[KncaCertType]>,
    ) -> HostResult<bool> {
        if let Some((_, _, known)) = self
            .evaluated
            .iter()
            .find(|(f, k, _)| f.as_ref() == filter && k.as_deref() == kinds)
        {
            return Ok(*known);
        }
        if self.evaluated.len() >= MAX_EVALUATIONS {
            return Err(HostError::new(
                ErrorCode::Limit,
                format!("at most {MAX_EVALUATIONS} different key filters in a call"),
            ));
        }
        let answer = self.evaluate(filter, kinds)?;
        self.evaluated
            .push((filter.cloned(), kinds.map(<[_]>::to_vec), answer));
        Ok(answer)
    }

    fn evaluate(
        &self,
        filter: Option<&KeyFilter>,
        kinds: Option<&[KncaCertType]>,
    ) -> HostResult<bool> {
        let der = &self.interaction.bound_key().certificate;
        let cert: Certificate = oncl_pki::cert::parse(der)
            .map_err(|e| HostError::new(ErrorCode::Invalid, format!("not a certificate: {e}")))?;
        let info = cert_info(&cert);
        if let Some(kinds) = kinds {
            let types = kcert_types(&info);
            if !kinds.iter().any(|kind| types.contains(kind)) {
                return Ok(false);
            }
        }
        let Some(filter) = filter else {
            return Ok(true);
        };
        let live = availabilities(
            filter,
            &[(cert, info)],
            self.interaction.http(),
            self.interaction.ocsp_cache(),
            self.interaction.now(),
        );
        Ok(live.wait_settled() == [Availability::Enabled])
    }

    fn chosen(&self) -> Chosen {
        let key = self.interaction.bound_key();
        Chosen {
            handle: key.handle,
            alias: key.alias.clone(),
            certificate: Bytes::from(key.certificate.clone()),
        }
    }

    fn choose(&mut self, filter: &KeyFilter) -> HostResult<Option<Chosen>> {
        Ok(self.matches(Some(filter), None)?.then(|| self.chosen()))
    }

    fn flow_open(&mut self, args: FlowArgs) -> HostResult<FlowOutcome> {
        if self.flows.len() >= MAX_FLOWS {
            return Err(HostError::new(
                ErrorCode::Limit,
                format!("at most {MAX_FLOWS} key choices in a call"),
            ));
        }
        let kinds = args
            .knca_types
            .map(|names| {
                names
                    .iter()
                    .map(|name| {
                        KncaCertType::from_name(name).ok_or_else(|| {
                            HostError::new(ErrorCode::Invalid, format!("no Kalkan type {name:?}"))
                        })
                    })
                    .collect::<HostResult<Vec<_>>>()
            })
            .transpose()?;
        let matched = match args.checks {
            FlowChecks::Settled => self.matches(None, kinds.as_deref())?,
            FlowChecks::Live { filter, more } => {
                let filter = key_filter(*filter, filter_more(*more)?)?;
                self.matches(Some(&filter), kinds.as_deref())?
            }
        };
        // At most MAX_FLOWS, which fits a u32.
        let id = self.flows.len() as u32;
        self.flows.push(matched);
        let key = self.interaction.bound_key();
        Ok(FlowOutcome {
            opened: matched.then(|| FlowOpened {
                flow: id,
                keys: vec![FlowKey {
                    alias: key.alias.clone(),
                    certificate: Bytes::from(key.certificate.clone()),
                }],
            }),
            wrong_pin: None,
        })
    }

    fn flow_pick(&mut self, args: PickArgs) -> HostResult<Option<Chosen>> {
        match self.flows.get(args.flow as usize) {
            Some(true) => Ok(Some(self.chosen())),
            _ => Err(HostError::new(
                ErrorCode::Invalid,
                format!("no key choice {} in this call", args.flow),
            )),
        }
    }
}
