//! What an operator grant of a plugin operation means on the server
//! (docs/design/manual-plugins.md 4.7/4.8, rulings R3, R14).
//!
//! * A plugin WITHOUT `[[operations]]` is unchanged: the grant is the operator's labels
//!   (token, operation, imports, keys), nothing is ticketed, the audit says `declared=false`
//!   and the start-up log warns that no signature option is enforced.
//! * A plugin WITH declarations is granted only under a declared operation that says
//!   `server = true`; the grant's imports must be among the declared ones (an empty list
//!   means all of them); keys and `plugin_bytes` need a declared key use; PKI endpoints need
//!   a declared `network = "pki"`. A grant that is wider than the declaration is skipped with
//!   an error that names the declaration; the other grants and the server run.
//! * Core ticketes every key use of a declared operation from the very arguments it runs and
//!   forces the declared options. The server cannot bind the signed bytes to a document (the
//!   arguments are free JSON of the client), so [`ServerPluginPolicy`], consulted by the audit
//!   guard before any BEGIN is written, lets a ticketed key use through only when the grant
//!   carries `plugin_bytes = true`, names the key, matches the installed package and the
//!   declared options, and is the first use of that request (operation id).
use crate::{
    audit::{PluginGrantFacts, PluginTicketPolicy},
    config::PluginGrant,
};
use oncl_core::{
    OperationId,
    keys::KeyId,
    plugins::{CallerContext, PackageHash, PluginUse, TicketRefusal},
};
use oncl_pdk::abi::Import;
use oncl_plugin::{
    Manifest,
    operations::{KeyKind, Network, Operation},
};
use std::{
    collections::{HashSet, VecDeque},
    io,
    sync::{Mutex, PoisonError},
};

/// Refusals kept for the HTTP layer to drain (one per refused operation).
const REFUSAL_MEMORY: usize = 256;

/// The verdict on one configured grant.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The grant is installed with these exact imports.
    Keep {
        imports: Vec<Import>,
        /// The operation is declared in the manifest: tickets and the profile apply.
        declared: bool,
        /// Start-up warnings about the grant.
        warnings: Vec<String>,
    },
    /// The grant is wider than the declaration (or meaningless there): skipped, with this
    /// error for the log.
    Skip(String),
}

/// Judges `grant` of plugin `plugin` against its `manifest`. `Err` only for a grant that is
/// not a valid configuration at all (an import name that does not exist).
pub(crate) fn judge(plugin: &str, manifest: &Manifest, grant: &PluginGrant) -> io::Result<Verdict> {
    let mut imports = grant
        .imports
        .iter()
        .map(|name| {
            Import::ALL
                .iter()
                .copied()
                .find(|import| import.name() == name)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "unknown plugin import"))
        })
        .collect::<io::Result<Vec<_>>>()?;
    let who = format!(
        "token {:?} operation {:?} of plugin {plugin}",
        grant.token, grant.operation
    );
    if manifest.operations().is_empty() {
        let mut warnings = vec![format!(
            "grant without declaration ({who}): the plugin declares no operations, so its signature options are not enforced"
        )];
        if grant.plugin_bytes {
            warnings.push(format!(
                "plugin_bytes of {who} has no effect: the plugin declares no operations"
            ));
        }
        return Ok(Verdict::Keep {
            imports,
            declared: false,
            warnings,
        });
    }
    let declared_names: Vec<&str> = manifest.operations().iter().map(Operation::name).collect();
    let Some(operation) = manifest
        .operations()
        .iter()
        .find(|o| o.name() == grant.operation)
    else {
        return Ok(Verdict::Skip(format!(
            "plugin {plugin} declares operations {declared_names:?}; the grant for the undeclared operation {:?} of token {:?} is skipped",
            grant.operation, grant.token
        )));
    };
    let skip = |why: String| Ok(Verdict::Skip(format!("{who}: grant skipped: {why}")));
    if !operation.server() {
        return skip("the operation does not declare `server = true`".into());
    }
    if !operation.runnable() {
        return skip("the operation is not runnable (derived content)".into());
    }
    let declared_imports = operation.uses().imports();
    if imports.is_empty() {
        imports = declared_imports.to_vec();
    } else if let Some(extra) = imports.iter().find(|i| !declared_imports.contains(i)) {
        return skip(format!(
            "the import {:?} is not among the declared imports {:?}",
            extra.name(),
            declared_imports
                .iter()
                .map(Import::name)
                .collect::<Vec<_>>()
        ));
    }
    let key_declared = !operation.uses().keys().is_empty();
    if !grant.keys.is_empty() && !key_declared {
        return skip("it names keys but the operation declares no key use".into());
    }
    if grant.plugin_bytes && !key_declared {
        return skip("plugin_bytes is set but the operation declares no key use".into());
    }
    if !grant.pki_endpoints.is_empty() && !matches!(operation.uses().network(), Network::Pki) {
        return skip(
            "it names PKI endpoints but the operation does not declare `network = \"pki\"`".into(),
        );
    }
    let mut warnings = Vec::new();
    if key_declared && !grant.keys.is_empty() && !grant.plugin_bytes {
        warnings.push(format!(
            "{who}: names keys without plugin_bytes = true: every key use will be refused (not-granted)"
        ));
    }
    Ok(Verdict::Keep {
        imports,
        declared: true,
        warnings,
    })
}

struct Rule {
    token: String,
    plugin: String,
    operation: String,
    grant_id: String,
    plugin_bytes: bool,
    package: PackageHash,
    keys: Vec<KeyId>,
    /// Declared key uses: the kind and the SHA-256 of the declared options. `None` when the
    /// declared profile names a parameter the server has no value for.
    uses: Vec<(KeyKind, Option<[u8; 32]>)>,
}

/// The server's check of a ticketed plugin key use (a declared operation), consulted by the
/// audit guard in `before_use`: no journal record and no key use before it says yes.
#[derive(Default)]
pub struct ServerPluginPolicy {
    rules: Vec<Rule>,
    /// Operations that used their one key use and have not ended yet (forgotten by
    /// [`PluginTicketPolicy::operation_ended`]; never evicted by anything else).
    spent: Mutex<HashSet<OperationId>>,
    refusals: Mutex<VecDeque<(OperationId, TicketRefusal)>>,
}

impl ServerPluginPolicy {
    /// Adds the rule of one kept grant of a declared operation.
    pub(crate) fn add(
        &mut self,
        plugin: &str,
        grant: &PluginGrant,
        package: PackageHash,
        operation: &Operation,
    ) -> io::Result<()> {
        let keys = grant
            .keys
            .iter()
            .map(|name| {
                KeyId::new(name)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key name"))
            })
            .collect::<io::Result<Vec<_>>>()?;
        let none: &dyn Fn(&str) -> Option<String> = &|_| None;
        self.rules.push(Rule {
            token: grant.token.clone(),
            plugin: plugin.to_owned(),
            operation: grant.operation.clone(),
            grant_id: format!("{}:{plugin}:{}", grant.token, grant.operation),
            plugin_bytes: grant.plugin_bytes,
            package,
            keys,
            uses: operation
                .uses()
                .keys()
                .iter()
                .map(|use_| (use_.kind(), use_.options_sha256(none)))
                .collect(),
        });
        Ok(())
    }

    /// The first refusal this policy gave for `operation` (removing it), for the typed error
    /// answer. `None` when the policy refused nothing for it.
    pub(crate) fn take_refusal(&self, operation: OperationId) -> Option<TicketRefusal> {
        let mut log = self.refusals.lock().unwrap_or_else(PoisonError::into_inner);
        let at = log.iter().position(|(id, _)| *id == operation)?;
        log.remove(at).map(|(_, refusal)| refusal)
    }

    /// How many operations hold a spent use (tests).
    #[cfg(test)]
    fn spent_operations(&self) -> usize {
        self.spent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    fn decide(&self, operation: OperationId, ticket: &PluginUse) -> Result<&Rule, TicketRefusal> {
        let CallerContext::ServiceClient(token) = ticket.caller() else {
            return Err(TicketRefusal::Caller);
        };
        let rule = self
            .rules
            .iter()
            .find(|r| {
                r.token == *token
                    && r.plugin == ticket.identity().id
                    && r.operation == ticket.operation()
            })
            .filter(|r| r.plugin_bytes)
            .ok_or(TicketRefusal::NotGranted)?;
        if ticket.identity().package != rule.package {
            return Err(TicketRefusal::Identity);
        }
        if ticket.max_uses() != oncl_plugin::operations::MAX_USES {
            return Err(TicketRefusal::Uses);
        }
        if !rule.keys.contains(ticket.key()) {
            return Err(TicketRefusal::Key);
        }
        let Some((_, options)) = rule.uses.iter().find(|(kind, _)| *kind == ticket.kind()) else {
            return Err(TicketRefusal::Kind);
        };
        // A declared profile that names a parameter cannot be matched without a value the
        // server has no way to receive: refused, never guessed.
        if *options != Some(*ticket.options_sha256()) {
            return Err(TicketRefusal::Options);
        }
        let mut spent = self.spent.lock().unwrap_or_else(PoisonError::into_inner);
        if !spent.insert(operation) {
            return Err(TicketRefusal::AlreadyUsed);
        }
        Ok(rule)
    }
}

impl PluginTicketPolicy for ServerPluginPolicy {
    fn operation_ended(&self, operation: OperationId) {
        self.spent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&operation);
    }
    fn check(
        &self,
        operation_id: OperationId,
        ticket: &PluginUse,
    ) -> Result<PluginGrantFacts, TicketRefusal> {
        match self.decide(operation_id, ticket) {
            Ok(rule) => Ok(PluginGrantFacts {
                grant_id: rule.grant_id.clone(),
                declared: true,
            }),
            Err(refusal) => {
                let mut log = self.refusals.lock().unwrap_or_else(PoisonError::into_inner);
                if log.len() == REFUSAL_MEMORY {
                    log.pop_front();
                }
                log.push_back((operation_id, refusal));
                Err(refusal)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DECLARED: &str = r#"id = "test.declared"
name.ru = "s"
name.kk = "s"
name.en = "s"
version = "1.0.0"
min_core = "0.1.0-alpha.7"
modules = ["test.declared.module"]
[capabilities]
keys = true
[[operations]]
name = "run"
module = "test.declared.module"
server = true
request = '{"module":"test.declared.module","method":"m","args":["{file:base64}"]}'
label = { ru = "а", kk = "ә", en = "a" }
[[operations.params]]
name = "file"
kind = "document"
max_bytes = 4096
[operations.uses]
imports = ["keys_sign_raw", "hash"]
network = "pki"
[[operations.uses.key]]
kind = "raw"
content = "param:file"

[[operations]]
name = "plain"
module = "test.declared.module"
server = true
request = '{"module":"test.declared.module","method":"m","args":[]}'
label = { ru = "а", kk = "ә", en = "a" }
[operations.uses]
imports = ["hash"]
network = "none"

[[operations]]
name = "manual-only"
module = "test.declared.module"
manual = true
server = false
request = '{"module":"test.declared.module","method":"m","args":["{file:base64}"]}'
label = { ru = "а", kk = "ә", en = "a" }
[[operations.params]]
name = "file"
kind = "document"
max_bytes = 4096
[operations.uses]
imports = ["hash"]
network = "none"
"#;
    const PLAIN: &str = r#"id = "test.plain"
name.ru = "s"
name.kk = "s"
name.en = "s"
version = "1.0.0"
min_core = "0.1.0"
modules = ["test.plain.module"]
"#;

    fn grant(operation: &str, imports: &[&str], keys: &[&str], plugin_bytes: bool) -> PluginGrant {
        PluginGrant {
            token: "svc".into(),
            operation: operation.into(),
            imports: imports.iter().map(|s| (*s).into()).collect(),
            keys: keys.iter().map(|s| (*s).into()).collect(),
            plugin_bytes,
            pki_endpoints: Vec::new(),
        }
    }
    fn declared() -> Manifest {
        Manifest::from_toml(DECLARED).unwrap()
    }
    fn skipped(verdict: io::Result<Verdict>) -> String {
        match verdict.unwrap() {
            Verdict::Skip(error) => error,
            other => panic!("expected a skip, got {other:?}"),
        }
    }

    #[test]
    fn a_plugin_without_declarations_keeps_its_grant_with_a_warning() {
        let manifest = Manifest::from_toml(PLAIN).unwrap();
        let Verdict::Keep {
            imports,
            declared,
            warnings,
        } = judge(
            "test.plain",
            &manifest,
            &grant("anything", &["hash"], &[], false),
        )
        .unwrap()
        else {
            panic!("kept")
        };
        assert_eq!(imports, [Import::Hash]);
        assert!(!declared);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("not enforced"), "{warnings:?}");
    }

    #[test]
    fn plugin_bytes_on_a_plugin_without_declarations_is_inert_and_said_so() {
        let manifest = Manifest::from_toml(PLAIN).unwrap();
        let Verdict::Keep { warnings, .. } = judge(
            "test.plain",
            &manifest,
            &grant("op", &["keys_sign_raw"], &["k"], true),
        )
        .unwrap() else {
            panic!("kept")
        };
        assert!(
            warnings.iter().any(|w| w.contains("no effect")),
            "{warnings:?}"
        );
    }

    #[test]
    fn an_undeclared_operation_is_skipped_naming_the_declared_ones() {
        let error = skipped(judge(
            "test.declared",
            &declared(),
            &grant("legacy", &["hash"], &[], false),
        ));
        assert!(
            error.contains("\"run\"") && error.contains("\"legacy\""),
            "{error}"
        );
    }

    #[test]
    fn an_operation_that_is_not_for_the_server_is_skipped() {
        let error = skipped(judge(
            "test.declared",
            &declared(),
            &grant("manual-only", &["hash"], &[], false),
        ));
        assert!(error.contains("server = true"), "{error}");
    }

    #[test]
    fn imports_beyond_the_declaration_are_skipped_and_empty_means_all_declared() {
        let error = skipped(judge(
            "test.declared",
            &declared(),
            &grant("run", &["keys_sign_cms"], &["k"], true),
        ));
        assert!(
            error.contains("keys_sign_cms") && error.contains("keys_sign_raw"),
            "{error}"
        );
        let Verdict::Keep {
            imports, declared, ..
        } = judge(
            "test.declared",
            &declared(),
            &grant("run", &[], &["k"], true),
        )
        .unwrap()
        else {
            panic!("kept")
        };
        assert!(declared);
        assert_eq!(imports, [Import::KeysSignRaw, Import::Hash]);
    }

    #[test]
    fn an_import_that_does_not_exist_is_a_configuration_error() {
        assert!(
            judge(
                "test.declared",
                &declared(),
                &grant("run", &["no_such_import"], &[], false)
            )
            .is_err()
        );
        let manifest = Manifest::from_toml(PLAIN).unwrap();
        assert!(
            judge(
                "test.plain",
                &manifest,
                &grant("run", &["no_such_import"], &[], false)
            )
            .is_err()
        );
    }

    #[test]
    fn keys_and_plugin_bytes_need_a_declared_key_use() {
        let manifest = Manifest::from_toml(&DECLARED.replace("name = \"manual-only\"\nmodule = \"test.declared.module\"\nmanual = true\nserver = false", "name = \"keyless\"\nmodule = \"test.declared.module\"\nmanual = true\nserver = true")).unwrap();
        let error = skipped(judge(
            "test.declared",
            &manifest,
            &grant("keyless", &["hash"], &["k"], false),
        ));
        assert!(error.contains("no key use"), "{error}");
        let error = skipped(judge(
            "test.declared",
            &manifest,
            &grant("keyless", &["hash"], &[], true),
        ));
        assert!(error.contains("plugin_bytes"), "{error}");
        assert!(matches!(
            judge(
                "test.declared",
                &manifest,
                &grant("keyless", &["hash"], &[], false)
            )
            .unwrap(),
            Verdict::Keep { declared: true, .. }
        ));
    }

    #[test]
    fn pki_endpoints_need_a_declared_pki_network() {
        let mut g = grant("plain", &["hash"], &[], false);
        g.pki_endpoints = vec!["https://ocsp.pki.gov.kz/".into()];
        let error = skipped(judge("test.declared", &declared(), &g));
        assert!(error.contains("network"), "{error}");
    }

    #[test]
    fn a_key_grant_without_plugin_bytes_is_kept_with_a_refusal_warning() {
        let Verdict::Keep { warnings, .. } = judge(
            "test.declared",
            &declared(),
            &grant("run", &["keys_sign_raw"], &["k"], false),
        )
        .unwrap() else {
            panic!("kept")
        };
        assert!(
            warnings.iter().any(|w| w.contains("not-granted")),
            "{warnings:?}"
        );
        let Verdict::Keep { warnings, .. } = judge(
            "test.declared",
            &declared(),
            &grant("run", &["keys_sign_raw"], &["k"], true),
        )
        .unwrap() else {
            panic!("kept")
        };
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    // --- the ticket policy: every rule killed on its own --------------------------------

    use oncl_core::plugins::{ContentBinding, PluginIdentity};

    fn package() -> PackageHash {
        oncl_core::plugins::loose_package_hash(DECLARED.as_bytes(), b"wasm")
    }
    fn policy(plugin_bytes: bool) -> ServerPluginPolicy {
        let manifest = declared();
        let operation = manifest
            .operations()
            .iter()
            .find(|o| o.name() == "run")
            .unwrap();
        let mut policy = ServerPluginPolicy::default();
        policy
            .add(
                "test.declared",
                &grant("run", &["keys_sign_raw"], &["ops-key"], plugin_bytes),
                package(),
                operation,
            )
            .unwrap();
        policy
    }
    fn operation_id(n: u64) -> OperationId {
        // Operation ids are assigned by the engine; tests take them from real contexts.
        use oncl_pki::resource::{OperationControl, ProcessingError, Progress};
        struct Control;
        impl OperationControl for Control {
            fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
                Ok(())
            }
        }
        let engine = oncl_core::Engine::new(oncl_core::EngineServices::hash_only(
            oncl_pki::resource::ResourceLimits::default(),
        ))
        .unwrap();
        let mut id = None;
        for _ in 0..=n {
            let ctx = engine
                .begin(
                    oncl_core::ExecutionGrant::new([oncl_core::Action::Hash]),
                    oncl_core::OperationPolicy::strict_online(),
                    std::sync::Arc::new(Control),
                )
                .unwrap();
            id = Some(ctx.id());
        }
        id.unwrap()
    }
    struct Ticket {
        plugin: &'static str,
        operation: &'static str,
        caller: CallerContext,
        package: PackageHash,
        kind: KeyKind,
        key: &'static str,
        options: Option<[u8; 32]>,
    }
    impl Default for Ticket {
        fn default() -> Self {
            Self {
                plugin: "test.declared",
                operation: "run",
                caller: CallerContext::ServiceClient("svc".into()),
                package: package(),
                kind: KeyKind::Raw,
                key: "ops-key",
                options: None,
            }
        }
    }
    impl Ticket {
        fn build(self) -> PluginUse {
            let manifest = declared();
            let none: &dyn Fn(&str) -> Option<String> = &|_| None;
            let declared = manifest.operations()[0].uses().keys()[0]
                .options_sha256(none)
                .unwrap();
            PluginUse::for_tests(
                PluginIdentity {
                    id: self.plugin.into(),
                    package: self.package,
                    version: "1.0.0".into(),
                },
                self.operation,
                self.caller,
                self.kind,
                1,
                KeyId::new(self.key).unwrap(),
                ContentBinding::bytes(b"anything the plugin chose"),
                self.options.unwrap_or(declared),
                [7; 32],
            )
        }
    }

    #[test]
    fn a_matching_ticket_under_plugin_bytes_is_allowed_once_per_operation() {
        let policy = policy(true);
        let id = operation_id(0);
        let facts = policy.check(id, &Ticket::default().build()).unwrap();
        assert_eq!(facts.grant_id, "svc:test.declared:run");
        assert!(facts.declared);
        assert_eq!(
            policy.check(id, &Ticket::default().build()).unwrap_err(),
            TicketRefusal::AlreadyUsed
        );
        // Another operation is its own first use.
        policy
            .check(operation_id(1), &Ticket::default().build())
            .unwrap();
    }

    #[test]
    fn every_deviation_from_the_grant_is_a_typed_refusal() {
        let cases: Vec<(&str, Ticket, TicketRefusal)> = vec![
            (
                "caller",
                Ticket {
                    caller: CallerContext::LocalOperator("svc".into()),
                    ..Ticket::default()
                },
                TicketRefusal::Caller,
            ),
            (
                "other token",
                Ticket {
                    caller: CallerContext::ServiceClient("other".into()),
                    ..Ticket::default()
                },
                TicketRefusal::NotGranted,
            ),
            (
                "plugin",
                Ticket {
                    plugin: "test.other",
                    ..Ticket::default()
                },
                TicketRefusal::NotGranted,
            ),
            (
                "operation",
                Ticket {
                    operation: "legacy",
                    ..Ticket::default()
                },
                TicketRefusal::NotGranted,
            ),
            (
                "package",
                Ticket {
                    package: oncl_core::plugins::loose_package_hash(b"x", b"y"),
                    ..Ticket::default()
                },
                TicketRefusal::Identity,
            ),
            (
                "key",
                Ticket {
                    key: "other-key",
                    ..Ticket::default()
                },
                TicketRefusal::Key,
            ),
            (
                "kind",
                Ticket {
                    kind: KeyKind::Cms,
                    ..Ticket::default()
                },
                TicketRefusal::Kind,
            ),
            (
                "options",
                Ticket {
                    options: Some([9; 32]),
                    ..Ticket::default()
                },
                TicketRefusal::Options,
            ),
        ];
        for (name, ticket, refusal) in cases {
            let policy = policy(true);
            let id = operation_id(0);
            assert_eq!(
                policy.check(id, &ticket.build()).unwrap_err(),
                refusal,
                "{name}"
            );
            assert_eq!(
                policy.take_refusal(id),
                Some(refusal),
                "{name}: logged for the answer"
            );
            assert_eq!(policy.take_refusal(id), None, "{name}: drained once");
        }
    }

    #[test]
    fn without_plugin_bytes_nothing_is_allowed_and_a_refusal_never_spends_the_use() {
        let policy = policy(false);
        let id = operation_id(0);
        assert_eq!(
            policy.check(id, &Ticket::default().build()).unwrap_err(),
            TicketRefusal::NotGranted
        );
        let granted = self::policy(true);
        assert_eq!(
            granted
                .check(
                    id,
                    &Ticket {
                        key: "other-key",
                        ..Ticket::default()
                    }
                    .build()
                )
                .unwrap_err(),
            TicketRefusal::Key
        );
        granted.check(id, &Ticket::default().build()).unwrap();
    }

    #[test]
    fn churn_of_other_operations_never_frees_a_spent_use_and_the_end_of_the_operation_does() {
        let policy = policy(true);
        let first = operation_id(0);
        policy.check(first, &Ticket::default().build()).unwrap();
        // 4104 other operations each take their one use while `first` is still running.
        for _ in 1..=4104 {
            let other = operation_id(0);
            policy.check(other, &Ticket::default().build()).unwrap();
            policy.operation_ended(other);
        }
        assert_eq!(
            policy.check(first, &Ticket::default().build()).unwrap_err(),
            TicketRefusal::AlreadyUsed
        );
        policy.operation_ended(first);
        assert_eq!(
            policy.spent_operations(),
            0,
            "nothing is remembered after the end"
        );
    }
}
