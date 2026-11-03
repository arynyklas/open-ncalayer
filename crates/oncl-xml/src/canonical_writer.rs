//! Shared canonical rendering state; adapters supply normalized values or raw spans.
use crate::{C14n, C14nProfile};
use oncl_pki::resource::{ProcessingError, ResourceReservation, ResourceScope};
use std::{collections::BTreeMap, io::Write};
pub(crate) const XML: &str = "http://www.w3.org/XML/1998/namespace";
pub(crate) type Result<T, E = ProcessingError> = std::result::Result<T, E>;
#[derive(Clone)]
pub(crate) struct Attribute<V> {
    pub namespace: String,
    pub local: String,
    pub qname: String,
    pub value: V,
}
struct Frame<V> {
    selected: bool,
    name: String,
    changes: Vec<(String, Option<String>)>,
    xml: Vec<Attribute<V>>,
    _guards: Option<(ResourceReservation, ResourceReservation)>,
}
pub(crate) struct CanonicalWriter<'a, V> {
    sink: &'a mut dyn Write,
    method: C14n,
    profile: C14nProfile,
    prefixes: &'a [String],
    bindings: BTreeMap<String, String>,
    frames: Vec<Frame<V>>,
    remaining: u64,
    initial_limit: u64,
    scope: Option<&'a ResourceScope>,
}
impl<'a, V: Clone> CanonicalWriter<'a, V> {
    pub fn new(
        sink: &'a mut dyn Write,
        method: C14n,
        profile: C14nProfile,
        prefixes: &'a [String],
        limit: u64,
        scope: Option<&'a ResourceScope>,
    ) -> Self {
        Self {
            sink,
            method,
            profile,
            prefixes,
            bindings: BTreeMap::new(),
            frames: Vec::new(),
            remaining: limit,
            initial_limit: limit,
            scope,
        }
    }
    pub fn put(&mut self, bytes: &[u8]) -> Result<()> {
        self.remaining = self
            .remaining
            .checked_sub(bytes.len() as u64)
            .ok_or(ProcessingError::InvalidInput("canonical work limit"))?;
        self.sink.write_all(bytes)?;
        Ok(())
    }
    pub fn escaped(&mut self, bytes: &[u8], attribute: bool) -> Result<()> {
        let mut start = 0;
        for (i, byte) in bytes.iter().copied().enumerate() {
            let replacement: Option<&[u8]> = match byte {
                b'&' => Some(b"&amp;"),
                b'<' => Some(b"&lt;"),
                b'>' if !attribute => Some(b"&gt;"),
                b'"' if attribute => Some(b"&quot;"),
                b'\r' => Some(b"&#xD;"),
                b'\n' if attribute => Some(b"&#xA;"),
                b'\t' if attribute => Some(b"&#x9;"),
                _ => None,
            };
            if let Some(replacement) = replacement {
                self.put(&bytes[start..i])?;
                self.put(replacement)?;
                start = i + 1;
            }
        }
        self.put(&bytes[start..])
    }
    pub fn selected(&self) -> bool {
        self.frames.last().is_some_and(|f| f.selected)
    }
    pub fn start<F>(
        &mut self,
        name: String,
        namespaces: Vec<(String, String)>,
        mut attrs: Vec<Attribute<V>>,
        selected: bool,
        mut value: F,
    ) -> Result<()>
    where
        F: FnMut(&V, &mut Self) -> Result<()>,
    {
        // Event scratch is separately admitted by the indexed adapter. These
        // guards cover retained frames/bindings, before their first allocation.
        let mut guards = if let Some(scope) = self.scope {
            let xml_bytes: usize = attrs
                .iter()
                .filter(|a| a.namespace == XML)
                .map(|a| {
                    a.namespace.len()
                        + a.local.len()
                        + a.qname.len()
                        + std::mem::size_of::<Attribute<V>>()
                })
                .sum();
            let bytes =
                (name.len() + 2 * xml_bytes + 4 * std::mem::size_of::<Attribute<V>>() + 512) as u64;
            Some((scope.reserve_memory(bytes)?, scope.reserve_metadata(bytes)?))
        } else {
            None
        };
        let xml = attrs
            .iter()
            .filter(|a| a.namespace == XML)
            .cloned()
            .collect();
        let mut changes = Vec::new();
        let mut _inheritance_guards = None;
        if selected {
            let apex = !self.selected();
            if apex && !self.method.is_exclusive() {
                if let Some(scope) = self.scope {
                    let bytes = self
                        .frames
                        .iter()
                        .flat_map(|f| &f.xml)
                        .map(|a| {
                            3 * (a.namespace.len()
                                + a.local.len()
                                + a.qname.len()
                                + std::mem::size_of::<Attribute<V>>()
                                + 256)
                        })
                        .sum::<usize>() as u64;
                    _inheritance_guards =
                        Some((scope.reserve_memory(bytes)?, scope.reserve_metadata(bytes)?));
                }
                let mut inherited = BTreeMap::new();
                for frame in &self.frames {
                    for a in &frame.xml {
                        match self.profile {
                            C14nProfile::Standard => {
                                inherited.insert(a.local.clone(), a.clone());
                            }
                            C14nProfile::KalkanLegacy => {
                                inherited
                                    .entry(a.local.clone())
                                    .or_insert_with(|| a.clone());
                            }
                        }
                    }
                }
                for a in &attrs {
                    if a.namespace == XML {
                        inherited.remove(&a.local);
                    }
                }
                attrs.extend(inherited.into_values());
            }
            let prefix = crate::parse::prefix(&name);
            let mut candidates = BTreeMap::new();
            for (p, u) in namespaces {
                let visible = p == prefix
                    || attrs
                        .iter()
                        .any(|a| a.qname.split_once(':').is_some_and(|(ap, _)| ap == p));
                if p != "xml"
                    && (!self.method.is_exclusive()
                        || visible
                        || self.prefixes.iter().any(|i| i == &p))
                {
                    candidates.insert(p, u);
                }
            }
            if prefix.is_empty() && !candidates.contains_key("") {
                candidates.insert(String::new(), String::new());
            }
            candidates.retain(|p, u| self.bindings.get(p).map(String::as_str).unwrap_or("") != u);
            if self.profile == C14nProfile::Standard
                && candidates.values().any(|uri| {
                    !uri.is_empty()
                        && !uri.split_once(':').is_some_and(|(scheme, _)| {
                            let mut bytes = scheme.bytes();
                            bytes.next().is_some_and(|b| b.is_ascii_alphabetic())
                                && bytes.all(|b| {
                                    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.')
                                })
                        })
                })
            {
                return Err(ProcessingError::InvalidInput(
                    "relative canonical namespace URI",
                ));
            }
            // Only newly rendered bindings survive this event. Charging full
            // unchanged in-scope contexts per depth would invent live storage.
            if let Some((memory, metadata)) = guards.as_mut() {
                let bytes = candidates
                    .iter()
                    .map(|(p, u)| 2 * p.len() + u.len() + 256)
                    .sum::<usize>() as u64;
                memory.grow(bytes)?;
                metadata.grow(bytes)?;
            }
            attrs.sort_unstable_by(|a, b| (&a.namespace, &a.local).cmp(&(&b.namespace, &b.local)));
            self.put(b"<")?;
            self.put(name.as_bytes())?;
            for (p, u) in candidates {
                self.put(b" xmlns")?;
                if !p.is_empty() {
                    self.put(b":")?;
                    self.put(p.as_bytes())?;
                }
                self.put(b"=\"")?;
                self.escaped(u.as_bytes(), true)?;
                self.put(b"\"")?;
                let previous = self.bindings.insert(p.clone(), u);
                changes.push((p, previous));
            }
            for a in attrs {
                self.put(b" ")?;
                self.put(a.qname.as_bytes())?;
                self.put(b"=\"")?;
                value(&a.value, self)?;
                self.put(b"\"")?;
            }
            self.put(b">")?;
        }
        self.frames.push(Frame {
            selected,
            name,
            changes,
            xml,
            _guards: guards,
        });
        Ok(())
    }
    pub fn end(&mut self) -> Result<()> {
        let frame = self
            .frames
            .pop()
            .ok_or(ProcessingError::InvalidInput("canonical frame"))?;
        if frame.selected {
            self.put(b"</")?;
            self.put(frame.name.as_bytes())?;
            self.put(b">")?;
        }
        for (p, old) in frame.changes {
            if let Some(u) = old {
                self.bindings.insert(p, u);
            } else {
                self.bindings.remove(&p);
            }
        }
        Ok(())
    }
    pub fn remaining(&self) -> u64 {
        self.remaining
    }
    pub fn written(&self) -> u64 {
        self.initial_limit - self.remaining
    }
    pub fn comments(&self) -> bool {
        self.method.with_comments()
    }
}
