//! Windows: crypt32 certificate stores and the chain engine.
//!
//! The user's own store is the `.Default` physical store of `CurrentUser\Root` (the
//! registry, `HKCU\Software\Microsoft\SystemCertificates\Root`). The logical
//! `CurrentUser\Root` also shows `LocalMachine\Root`, so it would report machine roots as the
//! user's and try to delete them from the machine store; it is used only to add, which is
//! what `certutil -user -addstore Root` does and where Windows shows its own security
//! warning with the SHA-1 thumbprint.

use std::ffi::c_void;
use std::io;
use std::mem::{offset_of, size_of};
use std::path::PathBuf;
use std::ptr;
use std::sync::{Mutex, PoisonError};

use windows_sys::Win32::Foundation::{CRYPT_E_EXISTS, ERROR_CANCELLED, GetLastError};
use windows_sys::Win32::Security::Cryptography::{
    AUTHTYPE_SERVER, CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, CERT_CHAIN_CONTEXT,
    CERT_CHAIN_DISABLE_AIA, CERT_CHAIN_PARA, CERT_CHAIN_POLICY_PARA, CERT_CHAIN_POLICY_SSL,
    CERT_CHAIN_POLICY_STATUS, CERT_CONTEXT, CERT_FIND_SHA1_HASH, CERT_OPEN_STORE_FLAGS,
    CERT_STORE_ADD_NEW, CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_MEMORY,
    CERT_STORE_PROV_PHYSICAL_W, CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG,
    CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY_ID,
    CERT_SYSTEM_STORE_LOCAL_MACHINE, CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE_ID,
    CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY_ID, CERT_SYSTEM_STORE_LOCATION_SHIFT,
    CERT_USAGE_MATCH, CRYPT_INTEGER_BLOB, CTL_USAGE, CertAddEncodedCertificateToStore,
    CertCloseStore, CertCreateCertificateContext, CertDeleteCertificateFromStore,
    CertDuplicateCertificateContext, CertFindCertificateInStore, CertFreeCertificateChain,
    CertFreeCertificateContext, CertGetCertificateChain, CertOpenStore,
    CertVerifyCertificateChainPolicy, HCERTCHAINENGINE, HCERTSTORE, HTTPSPolicyCallbackData,
    HTTPSPolicyCallbackData_0, USAGE_MATCH_TYPE_AND, X509_ASN_ENCODING, szOID_PKIX_KP_SERVER_AUTH,
};

use crate::{Cancelled, Certificate, InstallOutcome, StoreState, TrustReport, TrustStore};

const CURRENT_USER_GROUP_POLICY: u32 =
    CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT;
const LOCAL_MACHINE_GROUP_POLICY: u32 =
    CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT;
const LOCAL_MACHINE_ENTERPRISE: u32 =
    CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT;

/// `HRESULT_FROM_WIN32(ERROR_CANCELLED)`: some crypt32 paths report the declined security
/// warning as an `HRESULT`.
const HRESULT_CANCELLED: u32 = 0x8007_0000 | ERROR_CANCELLED;

/// The name the SSL policy checks the leaf against.
const SERVER_NAME: &str = "127.0.0.1";

/// `CurrentUser\Root`, or a store in memory for tests.
pub struct WindowsUserRoot {
    target: Target,
}

enum Target {
    CurrentUser,
    Memory(Mutex<Store>),
}

/// How [`WindowsUserRoot`] opens `CurrentUser\Root`.
#[derive(Clone, Copy)]
enum Access {
    Read,
    Add,
    Delete,
}

impl WindowsUserRoot {
    /// The real `CurrentUser\Root`. Adding to it makes Windows show its security warning;
    /// deleting from it may ask for confirmation too. `install` may answer `AlreadyPresent`
    /// when only `LocalMachine\Root` has the certificate (the logical store it adds to shows
    /// both), while `contains` and `remove` see the user's own certificates only.
    pub fn current_user() -> Self {
        Self {
            target: Target::CurrentUser,
        }
    }

    /// An empty store in memory (`CERT_STORE_PROV_MEMORY`) with the same operations and no
    /// system dialogs: for tests.
    pub fn memory() -> io::Result<Self> {
        Ok(Self {
            target: Target::Memory(Mutex::new(Store::memory()?)),
        })
    }

    fn with_store<R>(
        &self,
        access: Access,
        f: impl FnOnce(&Store) -> io::Result<R>,
    ) -> io::Result<R> {
        match &self.target {
            Target::Memory(store) => f(&store.lock().unwrap_or_else(PoisonError::into_inner)),
            Target::CurrentUser => {
                let store = match access {
                    Access::Read => Store::physical(
                        CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_READONLY_FLAG,
                        "Root\\.Default",
                    ),
                    Access::Delete => {
                        Store::physical(CERT_SYSTEM_STORE_CURRENT_USER, "Root\\.Default")
                    }
                    Access::Add => Store::system(CERT_SYSTEM_STORE_CURRENT_USER, "Root"),
                }?;
                f(&store)
            }
        }
    }
}

impl TrustStore for WindowsUserRoot {
    fn contains(&self, ca: &Certificate) -> io::Result<bool> {
        self.with_store(Access::Read, |store| Ok(store.contains(ca)))
    }

    fn install(&self, ca: &Certificate) -> io::Result<InstallOutcome> {
        // Checked first so that a second click shows no security warning at all.
        if self.contains(ca)? {
            return Ok(InstallOutcome::AlreadyPresent);
        }
        self.with_store(Access::Add, |store| store.add(ca))
    }

    fn remove(&self, ca: &Certificate) -> io::Result<bool> {
        self.with_store(Access::Delete, |store| store.delete(ca))
    }
}

/// Read-only check against the real stores (opened with `CERT_STORE_READONLY_FLAG`) and the
/// current user's chain engine.
pub(crate) fn check(ca: &Certificate, leaf: &Certificate) -> TrustReport {
    let read_only = CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG;
    let user = Store::physical(CERT_SYSTEM_STORE_CURRENT_USER | read_only, "Root\\.Default");
    // Policy and machine stores that may not exist are skipped.
    let managed: Vec<Store> = [
        CURRENT_USER_GROUP_POLICY,
        CERT_SYSTEM_STORE_LOCAL_MACHINE,
        LOCAL_MACHINE_GROUP_POLICY,
        LOCAL_MACHINE_ENTERPRISE,
    ]
    .into_iter()
    .filter_map(|location| Store::system(location | read_only, "Root").ok())
    .collect();
    // A null engine is the current user's default one (`HCCE_CURRENT_USER`).
    report(
        ca,
        leaf,
        user.as_ref(),
        &managed,
        ptr::null_mut(),
        &firefox_roots(),
    )
}

/// [`check`] against the given stores and chain engine.
fn report(
    ca: &Certificate,
    leaf: &Certificate,
    user: Result<&Store, &io::Error>,
    managed: &[Store],
    engine: HCERTCHAINENGINE,
    firefox_roots: &[PathBuf],
) -> TrustReport {
    let os_store = match user {
        Ok(store) if store.contains(ca) => StoreState::User,
        _ if managed.iter().any(|store| store.contains(ca)) => StoreState::Managed,
        Ok(_) => StoreState::Absent,
        Err(_) => StoreState::Unknown,
    };
    TrustReport {
        os_store,
        os_chain_ok: chain_ok(leaf, engine).ok(),
        nss: Vec::new(),
        firefox_enterprise_roots: crate::firefox_enterprise_roots_report(firefox_roots),
    }
}

/// `%APPDATA%\Mozilla\Firefox`.
fn firefox_roots() -> Vec<PathBuf> {
    std::env::var_os("APPDATA")
        .map(|appdata| PathBuf::from(appdata).join("Mozilla").join("Firefox"))
        .into_iter()
        .collect()
}

/// Whether the engine builds a chain for `leaf` that passes the SSL server policy for
/// `127.0.0.1`. No network: AIA fetching is off and revocation is not checked (a local CA has
/// no CRL or OCSP).
fn chain_ok(leaf: &Certificate, engine: HCERTCHAINENGINE) -> io::Result<bool> {
    let leaf = Context::from_der(leaf.der())?;
    let mut usage = szOID_PKIX_KP_SERVER_AUTH.cast_mut();
    let para = CERT_CHAIN_PARA {
        // Only `RequestedUsage`: the size Windows 7 knows too.
        cbSize: offset_of!(CERT_CHAIN_PARA, RequestedIssuancePolicy) as u32,
        RequestedUsage: CERT_USAGE_MATCH {
            dwType: USAGE_MATCH_TYPE_AND,
            Usage: CTL_USAGE {
                cUsageIdentifier: 1,
                rgpszUsageIdentifier: &raw mut usage,
            },
        },
        ..Default::default()
    };
    let mut chain: *mut CERT_CHAIN_CONTEXT = ptr::null_mut();
    // SAFETY: valid context and parameters; `chain` receives an owned chain context.
    let built = unsafe {
        CertGetCertificateChain(
            engine,
            leaf.0,
            ptr::null(),
            ptr::null_mut(),
            &para,
            CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL | CERT_CHAIN_DISABLE_AIA,
            ptr::null(),
            &mut chain,
        )
    };
    if built == 0 {
        return Err(io::Error::last_os_error());
    }
    let chain = Chain(chain);

    let mut server_name: Vec<u16> = SERVER_NAME.encode_utf16().chain([0]).collect();
    let mut ssl = HTTPSPolicyCallbackData {
        Anonymous: HTTPSPolicyCallbackData_0 {
            cbSize: size_of::<HTTPSPolicyCallbackData>() as u32,
        },
        dwAuthType: AUTHTYPE_SERVER,
        fdwChecks: 0,
        pwszServerName: server_name.as_mut_ptr(),
    };
    let policy = CERT_CHAIN_POLICY_PARA {
        cbSize: size_of::<CERT_CHAIN_POLICY_PARA>() as u32,
        dwFlags: 0,
        pvExtraPolicyPara: (&raw mut ssl).cast::<c_void>(),
    };
    let mut status = CERT_CHAIN_POLICY_STATUS {
        cbSize: size_of::<CERT_CHAIN_POLICY_STATUS>() as u32,
        ..Default::default()
    };
    // SAFETY: `chain` is a valid chain context; the parameters outlive the call.
    let evaluated = unsafe {
        CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain.0, &policy, &mut status)
    };
    if evaluated == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(status.dwError == 0)
}

fn last_error() -> u32 {
    // SAFETY: no preconditions.
    unsafe { GetLastError() }
}

fn is_cancelled(code: u32) -> bool {
    code == ERROR_CANCELLED || code == HRESULT_CANCELLED
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

/// An open certificate store, closed on drop.
struct Store(HCERTSTORE);

// SAFETY: a crypt32 store handle has no thread affinity (it is not a COM object); the only
// shared use, `Target::Memory`, is serialized by a `Mutex`.
unsafe impl Send for Store {}

impl Drop for Store {
    fn drop(&mut self) {
        // SAFETY: an open store handle owned by `self`.
        unsafe { CertCloseStore(self.0, 0) };
    }
}

impl Store {
    fn open(
        provider: *const u8,
        flags: CERT_OPEN_STORE_FLAGS,
        para: *const c_void,
    ) -> io::Result<Self> {
        // SAFETY: `para` is null or a NUL-terminated UTF-16 string, as the provider expects.
        let handle = unsafe { CertOpenStore(provider, 0, 0, flags, para) };
        if handle.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(handle))
        }
    }

    fn memory() -> io::Result<Self> {
        Self::open(CERT_STORE_PROV_MEMORY, 0, ptr::null())
    }

    /// A logical system store (`name` like `Root`) at a location (`flags`).
    fn system(flags: u32, name: &str) -> io::Result<Self> {
        let name = wide(name);
        Self::open(CERT_STORE_PROV_SYSTEM_W, flags, name.as_ptr().cast())
    }

    /// A physical store (`name` like `Root\.Default`) at a location (`flags`).
    fn physical(flags: u32, name: &str) -> io::Result<Self> {
        let name = wide(name);
        Self::open(CERT_STORE_PROV_PHYSICAL_W, flags, name.as_ptr().cast())
    }

    fn contains(&self, ca: &Certificate) -> bool {
        Matches::new(self, ca).next_match().is_some()
    }

    fn add(&self, ca: &Certificate) -> io::Result<InstallOutcome> {
        let len = u32::try_from(ca.der().len()).map_err(io::Error::other)?;
        // SAFETY: `der` is valid for `len` bytes; no output context is requested.
        let added = unsafe {
            CertAddEncodedCertificateToStore(
                self.0,
                X509_ASN_ENCODING,
                ca.der().as_ptr(),
                len,
                CERT_STORE_ADD_NEW,
                ptr::null_mut(),
            )
        };
        if added != 0 {
            return Ok(InstallOutcome::Installed);
        }
        match last_error() {
            code if code == CRYPT_E_EXISTS as u32 => Ok(InstallOutcome::AlreadyPresent),
            code if is_cancelled(code) => Ok(InstallOutcome::CancelledByUser),
            code => Err(io::Error::from_raw_os_error(code as i32)),
        }
    }

    fn delete(&self, ca: &Certificate) -> io::Result<bool> {
        let mut removed = false;
        let mut matches = Matches::new(self, ca);
        while let Some(found) = matches.next_match() {
            // SAFETY: `found` is valid until the next search; deleting a duplicate keeps it so
            // (the documented way to delete during an enumeration). The delete call frees the
            // duplicate even when it fails.
            let deleted =
                unsafe { CertDeleteCertificateFromStore(CertDuplicateCertificateContext(found)) };
            if deleted == 0 {
                return Err(match last_error() {
                    code if is_cancelled(code) => io::Error::other(Cancelled),
                    code => io::Error::from_raw_os_error(code as i32),
                });
            }
            removed = true;
        }
        Ok(removed)
    }
}

/// The contexts of a store whose encoding is exactly the certificate's, found by its SHA-1
/// thumbprint. A yielded context stays valid until the next `next_match` or the drop.
struct Matches<'a> {
    store: &'a Store,
    der: &'a [u8],
    sha1: [u8; 20],
    current: *const CERT_CONTEXT,
}

impl<'a> Matches<'a> {
    fn new(store: &'a Store, ca: &'a Certificate) -> Self {
        Self {
            store,
            der: ca.der(),
            sha1: ca.sha1(),
            current: ptr::null(),
        }
    }

    fn next_match(&mut self) -> Option<*const CERT_CONTEXT> {
        let blob = CRYPT_INTEGER_BLOB {
            cbData: self.sha1.len() as u32,
            pbData: self.sha1.as_mut_ptr(),
        };
        loop {
            // SAFETY: `blob` points to the thumbprint; the call frees `current` (owned, or
            // null) and returns the next owned context or null.
            let found = unsafe {
                CertFindCertificateInStore(
                    self.store.0,
                    X509_ASN_ENCODING,
                    0,
                    CERT_FIND_SHA1_HASH,
                    (&raw const blob).cast(),
                    self.current,
                )
            };
            self.current = found;
            if found.is_null() {
                return None;
            }
            // SAFETY: a valid context; its encoded bytes live as long as the context.
            let encoded = unsafe {
                std::slice::from_raw_parts((*found).pbCertEncoded, (*found).cbCertEncoded as usize)
            };
            if encoded == self.der {
                return Some(found);
            }
        }
    }
}

impl Drop for Matches<'_> {
    fn drop(&mut self) {
        if !self.current.is_null() {
            // SAFETY: an owned context returned by the last search.
            unsafe { CertFreeCertificateContext(self.current) };
        }
    }
}

/// A certificate context not in any store, freed on drop.
struct Context(*const CERT_CONTEXT);

impl Context {
    fn from_der(der: &[u8]) -> io::Result<Self> {
        let len = u32::try_from(der.len()).map_err(io::Error::other)?;
        // SAFETY: `der` is valid for `len` bytes; crypt32 copies it.
        let context = unsafe { CertCreateCertificateContext(X509_ASN_ENCODING, der.as_ptr(), len) };
        if context.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(context))
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: an owned context.
        unsafe { CertFreeCertificateContext(self.0) };
    }
}

/// A chain context, freed on drop.
struct Chain(*mut CERT_CHAIN_CONTEXT);

impl Drop for Chain {
    fn drop(&mut self) {
        // SAFETY: an owned chain context.
        unsafe { CertFreeCertificateChain(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use windows_sys::Win32::Security::Cryptography::{
        CERT_CHAIN_ENGINE_CONFIG, CertCreateCertificateChainEngine, CertFreeCertificateChainEngine,
    };

    use super::*;
    use crate::tests::ca_and_leaf;

    /// A chain engine that trusts only the roots of `root` (`hExclusiveRoot`).
    struct Engine(HCERTCHAINENGINE);

    impl Engine {
        fn exclusive(root: &Store) -> Self {
            let config = CERT_CHAIN_ENGINE_CONFIG {
                cbSize: size_of::<CERT_CHAIN_ENGINE_CONFIG>() as u32,
                hExclusiveRoot: root.0,
                ..Default::default()
            };
            let mut engine = ptr::null_mut();
            // SAFETY: a valid config; `engine` receives an owned engine.
            let created = unsafe { CertCreateCertificateChainEngine(&config, &mut engine) };
            assert_ne!(created, 0, "{}", io::Error::last_os_error());
            Self(engine)
        }
    }

    impl Drop for Engine {
        fn drop(&mut self) {
            // SAFETY: an owned engine.
            unsafe { CertFreeCertificateChainEngine(self.0) };
        }
    }

    #[test]
    fn memory_store_install_contains_remove() {
        let (ca, _) = ca_and_leaf("one@host");
        let store = WindowsUserRoot::memory().unwrap();
        assert!(!store.contains(&ca).unwrap());
        assert!(!store.remove(&ca).unwrap());

        assert_eq!(store.install(&ca).unwrap(), InstallOutcome::Installed);
        assert!(store.contains(&ca).unwrap());
        assert_eq!(store.install(&ca).unwrap(), InstallOutcome::AlreadyPresent);

        assert!(store.remove(&ca).unwrap());
        assert!(!store.contains(&ca).unwrap());
        assert!(!store.remove(&ca).unwrap());
    }

    #[test]
    fn memory_store_add_reports_an_existing_certificate() {
        // The race behind `install`'s own check: the store refuses a duplicate itself.
        let (ca, _) = ca_and_leaf("race@host");
        let store = Store::memory().unwrap();
        assert_eq!(store.add(&ca).unwrap(), InstallOutcome::Installed);
        assert_eq!(store.add(&ca).unwrap(), InstallOutcome::AlreadyPresent);
        let mut matches = Matches::new(&store, &ca);
        assert!(matches.next_match().is_some());
        assert!(matches.next_match().is_none(), "one copy only");
    }

    #[test]
    fn memory_store_remove_leaves_other_certificates() {
        let (ours, _) = ca_and_leaf("ours@host");
        let (other, _) = ca_and_leaf("other@host");
        let store = WindowsUserRoot::memory().unwrap();
        assert_eq!(store.install(&ours).unwrap(), InstallOutcome::Installed);
        assert_eq!(store.install(&other).unwrap(), InstallOutcome::Installed);

        assert!(store.remove(&ours).unwrap());
        assert!(!store.contains(&ours).unwrap());
        assert!(store.contains(&other).unwrap());
    }

    #[test]
    fn report_against_memory_stores() {
        let (ca, leaf) = ca_and_leaf("check@host");
        let (stranger, _) = ca_and_leaf("stranger@host");
        let trusted = Store::memory().unwrap();
        trusted.add(&ca).unwrap();
        let empty = Store::memory().unwrap();

        let engine = Engine::exclusive(&trusted);
        let in_user = report(&ca, &leaf, Ok(&trusted), &[], engine.0, &[]);
        assert_eq!(in_user.os_store, StoreState::User);
        assert_eq!(in_user.os_chain_ok, Some(true));
        assert!(in_user.nss.is_empty());
        assert!(in_user.firefox_enterprise_roots.is_empty());

        let managed = Store::memory().unwrap();
        managed.add(&ca).unwrap();
        let in_machine = report(&ca, &leaf, Ok(&empty), &[managed], engine.0, &[]);
        assert_eq!(in_machine.os_store, StoreState::Managed);

        let untrusted = Engine::exclusive(&empty);
        let absent = report(&ca, &leaf, Ok(&empty), &[], untrusted.0, &[]);
        assert_eq!(absent.os_store, StoreState::Absent);
        assert_eq!(absent.os_chain_ok, Some(false));

        // Another CA does not vouch for our leaf.
        let wrong = Store::memory().unwrap();
        wrong.add(&stranger).unwrap();
        let wrong_engine = Engine::exclusive(&wrong);
        let not_ours = report(&ca, &leaf, Ok(&wrong), &[], wrong_engine.0, &[]);
        assert_eq!(not_ours.os_store, StoreState::Absent);
        assert_eq!(not_ours.os_chain_ok, Some(false));

        let unreadable = io::Error::other("no store");
        let unknown = report(&ca, &leaf, Err(&unreadable), &[], untrusted.0, &[]);
        assert_eq!(unknown.os_store, StoreState::Unknown);
    }

    #[test]
    fn check_reads_the_real_stores_without_failing() {
        // Read-only: a CA generated just now is in no store and nothing trusts its leaf.
        let (ca, leaf) = ca_and_leaf("fresh@host");
        let report = check(&ca, &leaf);
        assert_eq!(report.os_store, StoreState::Absent);
        assert_eq!(report.os_chain_ok, Some(false));
        assert!(report.nss.is_empty());
    }

    #[test]
    fn cancellation_codes() {
        assert!(is_cancelled(1223));
        assert!(is_cancelled(0x8007_04C7));
        assert!(!is_cancelled(CRYPT_E_EXISTS as u32));
    }
}
