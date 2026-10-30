//! The difference of two sets of facts (`diff.json`), what it calls for (an issue for the
//! core, one per plugin, or none for a repack, a re-signed manifest or a reachability note)
//! and its plain-text summary for `index.json`.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::facts::{
    ApiSurface, BundleFacts, CertRef, DistFacts, EmbeddedManifest, Facts, FetchStatus, JarFacts,
    KeystoreFacts,
};
use super::inventory::JreFacts;
use super::manifest::{DistUrl, SignerFacts};

/// A value before and after.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Change<T> {
    /// Before.
    pub before: T,
    /// After.
    pub after: T,
}

/// Items added to and removed from a set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "T: Ord + Deserialize<'de>"))]
pub struct SetDiff<T: Ord> {
    /// Added.
    pub added: BTreeSet<T>,
    /// Removed.
    pub removed: BTreeSet<T>,
}

impl<T: Ord> Default for SetDiff<T> {
    fn default() -> Self {
        SetDiff {
            added: BTreeSet::new(),
            removed: BTreeSet::new(),
        }
    }
}

impl<T: Ord + Clone> SetDiff<T> {
    /// `after` against `before`.
    pub fn of(before: &BTreeSet<T>, after: &BTreeSet<T>) -> SetDiff<T> {
        SetDiff {
            added: after.difference(before).cloned().collect(),
            removed: before.difference(after).cloned().collect(),
        }
    }
}

impl<T: Ord> SetDiff<T> {
    /// Nothing added or removed.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

fn change<T: PartialEq + Clone>(before: &T, after: &T) -> Option<Change<T>> {
    (before != after).then(|| Change {
        before: before.clone(),
        after: after.clone(),
    })
}

/// The difference of two sets of facts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactsDiff {
    /// No previous facts: the first entry.
    pub baseline: bool,
    /// The manifest.
    pub manifest: ManifestDiff,
    /// Bundles of the core (`required`).
    pub core: BTreeMap<String, BundleDiff>,
    /// Plugins.
    pub plugins: BTreeMap<String, BundleDiff>,
    /// Distributions.
    pub distributions: BTreeMap<String, DistDiff>,
    /// Notes (reachability), plain text.
    pub notes: Vec<String>,
}

/// The manifest's difference.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestDiff {
    /// `version`.
    pub version: Option<Change<String>>,
    /// `info`.
    pub info: Option<Change<String>>,
    /// `updurl`.
    pub updurl: Option<Change<String>>,
    /// `syspkgs`.
    pub syspkgs: SetDiff<String>,
    /// `disturls`, by type.
    pub disturls: Vec<Change<Option<DistUrl>>>,
    /// The signer.
    pub signer: Option<Change<SignerFacts>>,
    /// Unknown keys (as JSON text).
    pub extra: BTreeMap<String, Change<Option<String>>>,
    /// The file changed, nothing else: a new signature of the same content.
    pub resigned_only: bool,
}

impl ManifestDiff {
    /// No difference but a re-signature.
    pub fn is_empty(&self) -> bool {
        self.version.is_none()
            && self.info.is_none()
            && self.updurl.is_none()
            && self.syspkgs.is_empty()
            && self.disturls.is_empty()
            && self.signer.is_none()
            && self.extra.is_empty()
    }
}

/// A bundle's difference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum BundleDiff {
    /// New in the manifest.
    Added(Box<BundleFacts>),
    /// Gone from the manifest.
    Removed(Box<BundleFacts>),
    /// Changed.
    Changed {
        /// Fields of the manifest (and `jar`).
        fields: BTreeMap<String, Change<String>>,
        /// The API, when both JARs are known.
        api: Option<Box<ApiDiff>>,
        /// The rest of the JAR, when both are known.
        jar: Option<Box<JarDiff>>,
        /// The JAR changed but not its content, API or headers.
        repack_only: bool,
    },
}

/// The API's difference.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiDiff {
    /// Public classes.
    pub classes: SetDiff<String>,
    /// Methods of classes in both.
    pub methods: BTreeMap<String, SetDiff<String>>,
    /// Fields of classes in both.
    pub fields: BTreeMap<String, SetDiff<String>>,
    /// `NCALayerMethod` methods.
    pub ncalayer_methods: SetDiff<String>,
    /// Dotted names.
    pub names: SetDiff<String>,
    /// Error codes.
    pub error_codes: SetDiff<String>,
    /// URLs.
    pub urls: SetDiff<String>,
    /// Ports.
    pub ports: SetDiff<u16>,
}

impl ApiDiff {
    /// `after` against `before`.
    pub fn of(before: &ApiSurface, after: &ApiSurface) -> ApiDiff {
        let names = |a: &ApiSurface| a.classes.keys().cloned().collect::<BTreeSet<_>>();
        let mut methods = BTreeMap::new();
        let mut fields = BTreeMap::new();
        for (name, b) in &before.classes {
            if let Some(a) = after.classes.get(name) {
                let m = SetDiff::of(&b.methods, &a.methods);
                if !m.is_empty() {
                    methods.insert(name.clone(), m);
                }
                let f = SetDiff::of(&b.fields, &a.fields);
                if !f.is_empty() {
                    fields.insert(name.clone(), f);
                }
            }
        }
        ApiDiff {
            classes: SetDiff::of(&names(before), &names(after)),
            methods,
            fields,
            ncalayer_methods: SetDiff::of(&before.ncalayer_methods, &after.ncalayer_methods),
            names: SetDiff::of(&before.names, &after.names),
            error_codes: SetDiff::of(&before.error_codes, &after.error_codes),
            urls: SetDiff::of(&before.urls, &after.urls),
            ports: SetDiff::of(&before.ports, &after.ports),
        }
    }

    /// No difference.
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty()
            && self.methods.is_empty()
            && self.fields.is_empty()
            && self.ncalayer_methods.is_empty()
            && self.names.is_empty()
            && self.error_codes.is_empty()
            && self.urls.is_empty()
            && self.ports.is_empty()
    }
}

/// The rest of a JAR's difference.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JarDiff {
    /// Library classes by package.
    pub libraries: BTreeMap<String, Change<u32>>,
    /// Native files.
    pub natives: SetDiff<String>,
    /// Keystores.
    pub keystores: BTreeMap<String, KeystoreDiff>,
    /// Signature blocks.
    pub signers: BTreeMap<String, Change<Option<CertRef>>>,
    /// Allowed `MANIFEST.MF` headers.
    pub manifest_mf: BTreeMap<String, Change<Option<String>>>,
}

/// A keystore's difference: `alias sha256` lines.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeystoreDiff {
    /// Trusted certificates.
    pub trusted: SetDiff<String>,
    /// Private key entries (their first certificate).
    pub private: SetDiff<String>,
}

impl JarDiff {
    fn of(before: &JarFacts, after: &JarFacts) -> JarDiff {
        let mut libraries = BTreeMap::new();
        for k in before.libraries.keys().chain(after.libraries.keys()) {
            let b = before.libraries.get(k).copied().unwrap_or(0);
            let a = after.libraries.get(k).copied().unwrap_or(0);
            if let Some(c) = change(&b, &a) {
                libraries.insert(k.clone(), c);
            }
        }
        let keys = |m: &BTreeMap<String, String>| m.keys().cloned().collect::<BTreeSet<_>>();
        let store_lines = |k: &KeystoreFacts| {
            (
                k.trusted
                    .iter()
                    .map(|(a, c)| format!("{a} {}", c.sha256))
                    .collect::<BTreeSet<_>>(),
                k.private
                    .iter()
                    .map(|(a, c)| format!("{a} {}", c.first().map_or("", |c| c.sha256.as_str())))
                    .collect::<BTreeSet<_>>(),
            )
        };
        let mut keystores = BTreeMap::new();
        let empty = KeystoreFacts::default();
        for k in before.keystores.keys().chain(after.keystores.keys()) {
            let (bt, bp) = store_lines(before.keystores.get(k).unwrap_or(&empty));
            let (at, ap) = store_lines(after.keystores.get(k).unwrap_or(&empty));
            let d = KeystoreDiff {
                trusted: SetDiff::of(&bt, &at),
                private: SetDiff::of(&bp, &ap),
            };
            if !(d.trusted.is_empty() && d.private.is_empty()) {
                keystores.insert(k.clone(), d);
            }
        }
        let mut signers = BTreeMap::new();
        for k in before.signers.keys().chain(after.signers.keys()) {
            if let Some(c) = change(
                &before.signers.get(k).cloned(),
                &after.signers.get(k).cloned(),
            ) {
                signers.insert(k.clone(), c);
            }
        }
        let mut manifest_mf = BTreeMap::new();
        for k in before.manifest_mf.keys().chain(after.manifest_mf.keys()) {
            if let Some(c) = change(
                &before.manifest_mf.get(k).cloned(),
                &after.manifest_mf.get(k).cloned(),
            ) {
                manifest_mf.insert(k.clone(), c);
            }
        }
        JarDiff {
            libraries,
            natives: SetDiff::of(&keys(&before.natives), &keys(&after.natives)),
            keystores,
            signers,
            manifest_mf,
        }
    }
}

/// A distribution's difference.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DistDiff {
    /// New source.
    pub added: bool,
    /// Gone source.
    pub removed: bool,
    /// Fetch status.
    pub status: Option<Change<FetchStatus>>,
    /// SHA-256.
    pub sha256: Option<Change<Option<String>>>,
    /// Files added and removed.
    pub files: SetDiff<String>,
    /// Files in both with another SHA-256.
    pub changed_files: BTreeSet<String>,
    /// JARs by path.
    pub jars: BTreeMap<String, Change<Option<String>>>,
    /// The Java runtime.
    pub jre: Option<Change<Option<JreFacts>>>,
    /// Installer metadata, by part (as JSON text).
    pub meta: BTreeMap<String, Change<String>>,
    /// Embedded manifests.
    pub embedded_manifests: BTreeMap<String, Change<Option<EmbeddedManifest>>>,
    /// The file changed but not what is inside (same files, JARs repacked only).
    pub repack_only: bool,
}

impl DistDiff {
    /// Whether the content (not only reachability) changed.
    pub fn content_changed(&self) -> bool {
        let sha_changed = self
            .sha256
            .as_ref()
            .is_some_and(|c| c.before.is_some() && c.after.is_some());
        let new_with_content =
            self.added && self.sha256.as_ref().is_some_and(|c| c.after.is_some());
        (sha_changed || new_with_content) && !self.repack_only
    }
}

/// What an entry of the history is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// The first facts.
    Baseline,
    /// A change.
    Change,
    /// Only repacked JARs or a re-signed manifest.
    Repack,
}

/// A plugin line of the summary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginLine {
    /// Symbolic name.
    pub symname: String,
    /// Version before.
    pub from: Option<String>,
    /// Version after.
    pub to: Option<String>,
    /// `added`, `removed` or `changed`.
    pub change: String,
}

/// The summary of an entry, plain text.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    /// The core.
    pub core: Vec<String>,
    /// Plugins.
    pub plugins: Vec<PluginLine>,
    /// Distributions.
    pub distributions: Vec<String>,
    /// Notes.
    pub notes: Vec<String>,
}

/// The difference of `new` from `old` (none: the baseline).
pub fn diff(old: Option<&Facts>, new: &Facts) -> FactsDiff {
    let Some(old) = old else {
        return FactsDiff {
            baseline: true,
            manifest: ManifestDiff::default(),
            core: BTreeMap::new(),
            plugins: BTreeMap::new(),
            distributions: BTreeMap::new(),
            notes: Vec::new(),
        };
    };
    let mut notes = Vec::new();
    let (om, nm) = (&old.manifest, &new.manifest);
    let mut disturls = Vec::new();
    let kinds: BTreeSet<&String> = om
        .disturls
        .iter()
        .chain(&nm.disturls)
        .map(|d| &d.kind)
        .collect();
    for kind in kinds {
        let b = om.disturls.iter().find(|d| &d.kind == kind).cloned();
        let a = nm.disturls.iter().find(|d| &d.kind == kind).cloned();
        if let Some(c) = change(&b, &a) {
            disturls.push(c);
        }
    }
    let mut extra = BTreeMap::new();
    for k in om.extra.keys().chain(nm.extra.keys()) {
        let text = |m: &BTreeMap<String, serde_json::Value>| m.get(k).map(ToString::to_string);
        if let Some(c) = change(&text(&om.extra), &text(&nm.extra)) {
            extra.insert(k.clone(), c);
        }
    }
    let mut manifest = ManifestDiff {
        version: change(&om.version, &nm.version),
        info: change(&om.info, &nm.info),
        updurl: change(&om.updurl, &nm.updurl),
        syspkgs: SetDiff::of(&om.syspkgs, &nm.syspkgs),
        disturls,
        signer: change(&om.signer, &nm.signer),
        extra,
        resigned_only: false,
    };

    let mut core = BTreeMap::new();
    let mut plugins = BTreeMap::new();
    let names: BTreeSet<&String> = old.bundles.keys().chain(new.bundles.keys()).collect();
    let mut bundle_fields_changed = false;
    for name in names {
        let (b, a) = (old.bundles.get(name), new.bundles.get(name));
        let (d, required) = match (b, a) {
            (None, Some(a)) => (BundleDiff::Added(Box::new(a.clone())), a.required),
            (Some(b), None) => (BundleDiff::Removed(Box::new(b.clone())), b.required),
            (Some(b), Some(a)) => {
                if b.fetch != a.fetch {
                    notes.push(format!(
                        "{name}: загрузка {} → {}",
                        fetch_name(b.fetch),
                        fetch_name(a.fetch)
                    ));
                }
                match bundle_change(b, a, old, new) {
                    Some(d) => (d, a.required),
                    None => continue,
                }
            }
            (None, None) => continue,
        };
        bundle_fields_changed = true;
        if required {
            core.insert(name.clone(), d);
        } else {
            plugins.insert(name.clone(), d);
        }
    }

    let mut distributions = BTreeMap::new();
    let ids: BTreeSet<&String> = old
        .distributions
        .keys()
        .chain(new.distributions.keys())
        .collect();
    for id in ids {
        let d = dist_change(id, old, new, &mut notes);
        if d != DistDiff::default() {
            distributions.insert(id.clone(), d);
        }
    }
    manifest.resigned_only =
        om.sha256 != nm.sha256 && manifest.is_empty() && !bundle_fields_changed;
    FactsDiff {
        baseline: false,
        manifest,
        core,
        plugins,
        distributions,
        notes,
    }
}

fn fetch_name(s: FetchStatus) -> &'static str {
    match s {
        FetchStatus::Ok => "ok",
        FetchStatus::Pending => "pending",
        FetchStatus::Unreachable => "unreachable",
        FetchStatus::Refused => "refused",
        FetchStatus::HashMismatch => "hash_mismatch",
    }
}

fn bundle_change(b: &BundleFacts, a: &BundleFacts, old: &Facts, new: &Facts) -> Option<BundleDiff> {
    let mut fields = BTreeMap::new();
    let mut field = |name: &str, before: String, after: String| {
        if before != after {
            fields.insert(name.to_owned(), Change { before, after });
        }
    };
    field("name", b.name.clone(), a.name.clone());
    field("version", b.version.clone(), a.version.clone());
    field("required", b.required.to_string(), a.required.to_string());
    field("hidden", b.hidden.to_string(), a.hidden.to_string());
    field("banned", b.banned.to_string(), a.banned.to_string());
    field("info", b.info.clone(), a.info.clone());
    field("url", b.url.clone(), a.url.clone());
    field("hash", b.hash.clone(), a.hash.clone());
    field("csernum", b.csernum.clone(), a.csernum.clone());
    field("chash", b.chash.clone(), a.chash.clone());
    field(
        "extra",
        serde_json::to_string(&b.extra).unwrap_or_default(),
        serde_json::to_string(&a.extra).unwrap_or_default(),
    );
    let jars_known = b.jar.is_some() && a.jar.is_some();
    if jars_known {
        field(
            "jar",
            b.jar.clone().unwrap_or_default(),
            a.jar.clone().unwrap_or_default(),
        );
    }
    if fields.is_empty() {
        return None;
    }
    let (bj, aj) = (
        b.jar.as_ref().and_then(|s| old.jars.get(s)),
        a.jar.as_ref().and_then(|s| new.jars.get(s)),
    );
    let (api, jar, repack_only) = match (bj, aj) {
        (Some(bj), Some(aj)) if b.jar != a.jar => {
            let api = ApiDiff::of(&bj.api, &aj.api);
            let jar = JarDiff::of(bj, aj);
            let others = fields.keys().all(|k| k == "hash" || k == "jar");
            let repack = bj.content_sha256 == aj.content_sha256
                && api.is_empty()
                && jar.manifest_mf.is_empty()
                && others;
            (
                (!api.is_empty()).then(|| Box::new(api)),
                (jar != JarDiff::default()).then(|| Box::new(jar)),
                repack,
            )
        }
        _ => (None, None, false),
    };
    Some(BundleDiff::Changed {
        fields,
        api,
        jar,
        repack_only,
    })
}

fn dist_change(id: &str, old: &Facts, new: &Facts, notes: &mut Vec<String>) -> DistDiff {
    let (b, a) = (old.distributions.get(id), new.distributions.get(id));
    let empty = |url: &str| DistFacts {
        url: url.to_owned(),
        page: None,
        label: None,
        filename: None,
        size: None,
        sha256: None,
        published_sha1: None,
        format: None,
        status: FetchStatus::Pending,
        unpack: super::facts::UnpackStatus::Skipped {
            reason: String::new(),
        },
        files: BTreeMap::new(),
        jre: None,
        jars: BTreeMap::new(),
        embedded_manifests: BTreeMap::new(),
        meta: Default::default(),
    };
    let (added, removed) = (b.is_none(), a.is_none());
    let b_owned;
    let a_owned;
    let b = match b {
        Some(b) => b,
        None => {
            b_owned = empty(&a.expect("one of both").url);
            &b_owned
        }
    };
    let a = match a {
        Some(a) => a,
        None => {
            a_owned = empty(&b.url);
            &a_owned
        }
    };
    if removed {
        notes.push(format!("{id}: источник исчез"));
    }
    let status = change(&b.status, &a.status).filter(|_| !added && !removed);
    if let Some(c) = &status {
        notes.push(format!(
            "{id}: загрузка {} → {}",
            fetch_name(c.before),
            fetch_name(c.after)
        ));
    }
    // A failed fetch keeps no content: nothing to compare.
    if a.sha256.is_none() && !removed {
        return DistDiff {
            added,
            removed,
            status,
            ..DistDiff::default()
        };
    }
    let keys = |d: &DistFacts| d.files.keys().cloned().collect::<BTreeSet<_>>();
    let files = SetDiff::of(&keys(b), &keys(a));
    let changed_files: BTreeSet<String> = b
        .files
        .iter()
        .filter(|(p, f)| a.files.get(*p).is_some_and(|n| n.sha256 != f.sha256))
        .map(|(p, _)| p.clone())
        .collect();
    let mut jars = BTreeMap::new();
    for k in b.jars.keys().chain(a.jars.keys()) {
        if let Some(c) = change(&b.jars.get(k).cloned(), &a.jars.get(k).cloned()) {
            jars.insert(k.clone(), c);
        }
    }
    let meta_parts = |d: &DistFacts| -> BTreeMap<String, String> {
        match serde_json::to_value(&d.meta) {
            Ok(serde_json::Value::Object(m)) => {
                m.into_iter().map(|(k, v)| (k, v.to_string())).collect()
            }
            _ => BTreeMap::new(),
        }
    };
    let (bm, am) = (meta_parts(b), meta_parts(a));
    let mut meta = BTreeMap::new();
    for k in bm.keys().chain(am.keys()) {
        let get = |m: &BTreeMap<String, String>| m.get(k).cloned().unwrap_or_default();
        if let Some(c) = change(&get(&bm), &get(&am)) {
            meta.insert(k.clone(), c);
        }
    }
    let mut embedded = BTreeMap::new();
    for k in b
        .embedded_manifests
        .keys()
        .chain(a.embedded_manifests.keys())
    {
        if let Some(c) = change(
            &b.embedded_manifests.get(k).cloned(),
            &a.embedded_manifests.get(k).cloned(),
        ) {
            embedded.insert(k.clone(), c);
        }
    }
    let sha256 = change(&b.sha256, &a.sha256).filter(|_| !removed);
    let repacked_jar = |path: &String| {
        let (Some(bs), Some(as_)) = (b.jars.get(path), a.jars.get(path)) else {
            return false;
        };
        match (old.jars.get(bs), new.jars.get(as_)) {
            (Some(bj), Some(aj)) => bj.content_sha256 == aj.content_sha256 && bj.api == aj.api,
            _ => false,
        }
    };
    // A repack only where both sides were inventoried: without files there is nothing to
    // compare, and any change of installer metadata is a change.
    let inventoried = |d: &DistFacts| d.unpack == super::facts::UnpackStatus::Ok;
    let repack_only = !added
        && !removed
        && sha256.is_some()
        && inventoried(b)
        && inventoried(a)
        && meta.is_empty()
        && files.is_empty()
        && changed_files.iter().all(repacked_jar)
        && jars.keys().all(repacked_jar)
        && b.jre == a.jre
        && embedded
            .values()
            .all(|c| c.before.as_ref().map(|m| &m.version) == c.after.as_ref().map(|m| &m.version));
    DistDiff {
        added,
        removed,
        status,
        sha256,
        files,
        changed_files,
        jars,
        jre: change(&b.jre, &a.jre),
        meta,
        embedded_manifests: embedded,
        repack_only,
    }
}

impl FactsDiff {
    /// Nothing differs.
    pub fn is_empty(&self) -> bool {
        !self.baseline
            && self.manifest == ManifestDiff::default()
            && self.core.is_empty()
            && self.plugins.is_empty()
            && self.distributions.is_empty()
            && self.notes.is_empty()
    }

    /// Whether the core needs an issue: the manifest (but a re-signature), a bundle of the
    /// core (but a repack) or the content of a distribution (but a repack) changed.
    pub fn needs_core_issue(&self) -> bool {
        !self.baseline
            && (!self.manifest.is_empty()
                || self.core.values().any(|d| !is_repack(d))
                || self.distributions.values().any(DistDiff::content_changed))
    }

    /// The plugins that need an issue.
    pub fn plugin_issues(&self) -> impl Iterator<Item = (&String, &BundleDiff)> {
        self.plugins
            .iter()
            .filter(move |(_, d)| !self.baseline && !is_repack(d))
    }

    /// What the entry is.
    pub fn kind(&self) -> EntryKind {
        if self.baseline {
            EntryKind::Baseline
        } else if self.needs_core_issue() || self.plugin_issues().next().is_some() {
            EntryKind::Change
        } else if self.manifest.resigned_only
            || self
                .core
                .values()
                .chain(self.plugins.values())
                .any(is_repack)
            || self.distributions.values().any(|d| d.repack_only)
        {
            EntryKind::Repack
        } else {
            EntryKind::Change
        }
    }

    /// The plain-text summary.
    pub fn summary(&self, old: Option<&Facts>, new: &Facts) -> Summary {
        let mut s = Summary::default();
        if self.baseline {
            s.core
                .push(format!("NCALayer {}: первые факты", new.manifest.version));
            return s;
        }
        if let Some(v) = &self.manifest.version {
            s.core
                .push(plain(&format!("NCALayer {} → {}", v.before, v.after)));
        }
        if self.manifest.signer.is_some() {
            s.core
                .push("Сменился сертификат подписи манифеста".to_owned());
        }
        if self.manifest.resigned_only {
            s.notes
                .push("Манифест переподписан, содержимое то же".to_owned());
        }
        let version = |f: Option<&Facts>, name: &str| {
            f.and_then(|f| f.bundles.get(name))
                .map(|b| b.version.clone())
        };
        for (name, d) in &self.core {
            if is_repack(d) {
                s.notes
                    .push(plain(&format!("{name}: перепакован, содержимое то же")));
                continue;
            }
            let (from, to) = (version(old, name), version(Some(new), name));
            s.core.push(plain(&format!(
                "{name} {} → {}",
                from.as_deref().unwrap_or("—"),
                to.as_deref().unwrap_or("—")
            )));
        }
        for (name, d) in &self.plugins {
            if is_repack(d) {
                s.notes
                    .push(plain(&format!("{name}: перепакован, содержимое то же")));
                continue;
            }
            s.plugins.push(PluginLine {
                symname: plain(name),
                from: version(old, name).map(|v| plain(&v)),
                to: version(Some(new), name).map(|v| plain(&v)),
                change: match d {
                    BundleDiff::Added(_) => "added",
                    BundleDiff::Removed(_) => "removed",
                    BundleDiff::Changed { .. } => "changed",
                }
                .to_owned(),
            });
        }
        for (id, d) in &self.distributions {
            if d.repack_only {
                s.notes
                    .push(plain(&format!("{id}: перепакован, содержимое то же")));
            } else if d.content_changed() {
                let short = |v: &Option<String>| {
                    v.as_deref()
                        .map_or("—".to_owned(), |h| h[..h.len().min(16)].to_owned())
                };
                let c = d.sha256.as_ref().expect("content changed");
                s.distributions.push(plain(&format!(
                    "{id}: sha256 {} → {}",
                    short(&c.before),
                    short(&c.after)
                )));
            }
        }
        s.notes.extend(self.notes.iter().map(|n| plain(n)));
        s
    }
}

fn is_repack(d: &BundleDiff) -> bool {
    matches!(
        d,
        BundleDiff::Changed {
            repack_only: true,
            ..
        }
    )
}

/// `s` as plain text: no table, code or markup characters, one line.
pub fn plain(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '|' | '`' | '<' | '>' | '\n' | '\r' | '\t' => ' ',
            c => c,
        })
        .collect()
}
