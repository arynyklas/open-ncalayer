# OpenNCALayer

[Русский](README.md)

OpenNCALayer is an open-source Rust replacement for NCALayer, the signing daemon used by Kazakhstan's e-government services. Sites (egov.kz, public procurement, banks, e-document systems) that talk to the original over `wss://127.0.0.1:13579` are meant to work with OpenNCALayer unchanged: same protocol, same modules.

OpenNCALayer is an independent project and is not affiliated with the National Certification Authority of the Republic of Kazakhstan (NCA RK).

## Status

Early development; the first pre-release is `0.1.0-alpha.1` ([Releases](https://github.com/arynyklas/open-ncalayer/releases)). The original's protocol for file key stores works (the eGov login was checked on Windows 11 in Chrome, both over `wss` with the CA trusted and through the extension), as do NCA certificate validation, the browser extension and the tray program. Builds for Windows 7 SP1 x64 and x86 exist but have not yet run on a real Windows 7 (see [Windows 7](#windows-7)). Tokens, auto-update and the plugin registry are ahead (see the [roadmap](docs/design/roadmap.md)).

P1 provides:
- the `kz.gov.pki.knca.basics` module, method `sign`, formats `cms` and `raw`;
- PKCS#12 keys (`.p12`, `.pfx`): GOST 2004, GOST 2015-512, RSA;
- attached and detached signatures, co-signing, NCA timestamps (TSP);
- storage and key selection dialogs (Russian, Kazakh, English);
- a command-line TLS wizard: `openncalayer tls init|import|status` ([guide, in Russian](docs/user/tls.md));
- signature checking: `openncalayer cms-verify` — signatures, timestamps, certificate chains up to the NCA roots, validity periods and revocation (OCSP, CRL);
- a self-test page at `https://127.0.0.1:13579/` and a demo page at `https://127.0.0.1:13579/demo/`.

The second phase (P2) adds a browser extension: with it, sites work with OpenNCALayer without a trusted CA (see [Browser extension](#browser-extension)).

The third phase (P3) checks keys in the key dialog as the original does. The key certificate's chain is built to the embedded NCA roots or to the CAs of `signerParams.chain`; `chain: []` turns the check off. The anchor is a self-signed CA of the set or, as in the original, the topmost CA of the set found, so a `chain` of an intermediate CA alone works too. Revocation is checked with the NCA OCSP responder. A key without a chain is unavailable. A revoked key is marked «revoked DD.MM.YYYY» and is unavailable too, unless `signingParams` has `allowRevoked` (which the `raw` format ignores). As in the original, the NCA test PKI is not embedded: test-environment sites must pass `chain`.

The fourth phase (P4) completes the original's protocol: the `basics`, `commonUtils`, `Applet` (a subset) and `accessory` modules, XML signatures (XMLDSig), new keys and certificate requests, installing issued certificates, and the `JKS` storage read-only (see [Modules](#modules)).

The fifth phase (P5) makes OpenNCALayer a desktop program: a tray icon, a settings window, a TLS wizard with buttons that install certificates, mkcert, certificate expiry reminders, coexistence with the original NCALayer, and an About window (see [Desktop](#desktop)).

The sixth phase (P6) adds builds for Windows 7 SP1 x64 and x86, a regular Windows x86 build and support for the extension in Firefox ESR 115 (see [Windows 7](#windows-7)).

Manual test results: [`docs/dev/smoke-p1.md`](docs/dev/smoke-p1.md), [`docs/dev/smoke-p2.md`](docs/dev/smoke-p2.md), [`docs/dev/smoke-p3.md`](docs/dev/smoke-p3.md), [`docs/dev/smoke-p4.md`](docs/dev/smoke-p4.md), [`docs/dev/smoke-p5.md`](docs/dev/smoke-p5.md) and [`docs/dev/smoke-p6.md`](docs/dev/smoke-p6.md) (in Russian).

Documentation is written in Russian:
- [`docs/user/tls.md`](docs/user/tls.md) — the OpenNCALayer certificate: issuing, trusting, removing, re-issuing;
- [`docs/design/roadmap.md`](docs/design/roadmap.md) — decisions and roadmap;
- [`docs/original/architecture.md`](docs/original/architecture.md) — architecture of the original NCALayer.

### Modules

The modules answer as the original's modules of the same names do: reply shapes, error codes and texts, order of checks. The security policy is the original's too: there is no per-origin consent, and the methods the original runs without a dialog run without one here as well. These are commonUtils' `getActiveTokens` and `changeLocale`, the accessory's `getBundles` and `getServices`, and in the Applet `loadSlotList`, `getPublicPartInfo`, `getTryCount` and `resetStorage`, plus, for file storages, the methods that write key files: `genKeyPairAndGetPKCS10` creates them in a folder the page names, `setX509CertToKeyStore` and `setX509CertToKeyStoreAndChangePassword` rewrite key files in such a folder, and `changePassword` rewrites a key file the page names. The accessory's `installBundle` answers without a dialog too, but only because it never installs anything (D21); the original asks the user to confirm before it installs a module. The differences are listed in [Deviations of P4 from the original](#deviations-of-p4-from-the-original).

- `kz.gov.pki.knca.basics`:
  - `sign`, formats `cms`, `raw` and `xml`. For the eGov login (`format:"xml"`) the reply is `{"status":true,"body":{"result":["<signed XML>"]}}`, as from the original;
  - `PKIEssentials` (a request with `"class":"PKIEssentials"`): `generateCsr` creates keys in a folder the user picks and returns certificate requests (`{"pems":[…]}`); `importCertificate` installs the certificates the NCA issued next to those keys and changes the key files' password from `defaultPassword` to the one the user types (`{"result":true}`). Cancelling gives `{}`.
- `kz.gov.pki.knca.commonUtils`: `getActiveTokens`, `getKeyInfo`, `signXml`, `signXmls`, `createCMSSignatureFromBase64`, `createCMSSignatureFromFile`, `createCAdESFromBase64`, `createCAdESFromFile`, `createCAdESFromBase64Hash`, `applyCAdEST`, `showFileChooser`, `changeLocale`. The reply is `{"code":"200"|"500","message"?,"responseObject"?,"uuid"?}`. The module's dialogs are in Russian until a page calls `changeLocale` (`ru`, `kk`, `en`); the language chosen applies to every page.
- `kz.gov.pki.knca.applet.Applet`: the legacy module; a subset for file storages (see [Applet](#applet)). As in the original, it also answers requests without a `module`.
- `kz.gov.pki.ncalayerservices.accessory`: `getBundles`, `getServices` (the daemon's modules), `installBundle`, `showBundleManager`, `showSettings`, `showKeystoreExplorer`, `showAdesSigning`, `showAdesValidation`.

Storages:
- `PKCS12` (`.p12`, `.pfx`): read and write;
- `JKS`: read only, RSA and GOST keys;
- until P14, tokens (`AK…Store`) answer as if no device were connected: they are unavailable in the `basics` dialogs, commonUtils answers `storage.empty`, the Applet `EMPTY_SLOT`, `getActiveTokens` `[]`.

XML signatures (`basics` with `format:"xml"`, commonUtils `signXml` and `signXmls`, the Applet's `signXml`) have the shape Kalkan makes:
- the whole document: `ds:Signature` is the last child of the root element; one `Reference URI=""` with the enveloped-signature and Canonical XML with comments transforms; SignedInfo is canonicalized with Canonical XML 1.0;
- an element (a non-empty `tbsElementXPath` in commonUtils): the element must have an `Id` attribute, else the error has Kalkan's text; `Reference URI="#<Id>"` with the one transform Canonical XML with comments; SignedInfo with Exclusive XML Canonicalization; the signature goes into the element of `signatureParentElementXPath`;
- the algorithm follows the certificate's signature algorithm: GOST 34.10-2015-512, GOST 34.310-2004 or sha256RSA, with Kalkan's algorithm URIs;
- every call appends a new signature; DOCTYPE and external entities are refused.

Keys and certificate requests (`generateCsr`; the Applet's `genKeyPairAndGetPKCS10` differs, see [Applet](#applet)):
- `params[].algorithm`: GOST 34.10-2015-512 (`1.2.398.3.10.1.1.2.3.2`), GOST 34.310-2004 (`1.2.398.3.10.1.1.1.2`), sha256RSA (`1.2.840.113549.1.1.11`) of 2048, 3072 or 4096 bits;
- the key file is `<folder>/<prefix><key id>.p12` (`GOST512_`, `GOSTKNCA_`, `RSA256_`), PKCS#12 in Kalkan's profile, the key without a certificate; the key id is the SHA-1 of the public key BIT STRING;
- the request is PKCS#10 in PEM: subject from `dn`, SAN (`subjectAltNames` and `email`) and the KeyStoreInfo extension (`1.2.398.3.3.5`) with the key folder's path;
- `importCertificate` finds the key file in the folder by the certificate's SubjectKeyIdentifier, installs the certificate next to the key (a file with a non-GOST-2015 authentication certificate is renamed to `AUTH_<name>`), then changes the password.

XMLDSig and CMS signatures and our key files are checked in NCANode (Kalkan): [`docs/dev/interop-ncanode.md`](docs/dev/interop-ncanode.md) (in Russian).

### Certificate checking

Trust comes only from the embedded NCA certificates and `signerParams.chain`, as in the original. The OS and browser trust stores are not read.

The embedded certificates are the 10 CAs of the NCA production PKI from [`fixtures/nca/prod/`](fixtures/nca/prod/), compiled into the binary (`crates/oncl-pki/src/roots.rs`): `rcagost`, `ncagost`, `ncagost18`, `rcagost22`, `ncagost22`, `rcarsa`, `rcarsa20`, `ncarsa`, `ncarsa18`, `ncarsa22`. Their sha256 sums are in `fixtures/nca/SHA256SUMS`, and a test checks the embedded bytes against them. The NCA test PKI (`fixtures/nca/test/`) is not embedded, as in the original: test-environment sites and tests must pass `chain`.

`signerParams.chain` in `basics.sign`:
- absent or `null`: the embedded NCA set;
- `[]`: neither the chain nor OCSP is checked (the demo page sends this by default);
- an array of strings: a CA set replacing the embedded one. Each string is a certificate in PEM or base64 DER; spaces and line breaks are allowed. A string that does not parse gives the site `CERTIFICATE_PARSING_FAILURE` before the dialog. An entry that is not a string (a number, `null`) gives `INVOCATION_ERROR`, as in the original (Java `ClassCastException`/`NullPointerException`).

The chain is built from the key certificate up through the CA set by the rules of RFC 5280 §6.1: signatures, validity of every certificate, the issuers' `basicConstraints.cA` and `pathLen`, `keyCertSign` (if `keyUsage` is present), unknown critical extensions. Certificate policies and `nameConstraints` are not processed. Names are compared byte for byte. The issuer is a CA of the set with the same name whose signature verifies; among several candidates the one whose `subjectKeyIdentifier` equals the certificate's `authorityKeyIdentifier` is tried first. Validity is checked at the current time, and for any expired key at its `notAfter`: the chain of such a key is built, the key is shown as expired, and its revocation is still checked.

Key revocation is checked with OCSP when the key has a chain, is not disabled for another reason (EKU, IIN, BIN, serial number; an expired key is still checked), its certificate is an end entity and its AIA has an OCSP URL: a GET request with a SHA-1 `CertID` and no nonce, a 5 s timeout, at most 2 s of it to connect (as for TSP and CRL requests), 6 s in total per store; a responder that cannot be connected to (its address does not answer) ends the check after 2 s. A response is accepted when its responder (`byName` or `byKey`) has a full chain to an anchor of the same CA set at the current time and has the `OCSPSigning` EKU and `id-pkix-ocsp-nocheck`, the signature verifies, the `CertID` matches and the response is fresh. Only the `revoked` status disables a key. Without a network, on a timeout, a bad response or the `unknown` status the key stays available and the cause is logged (`warn`): offline, OCSP does not block signing.

`openncalayer cms-verify` checks a finished signature (step 4 of [Build and run](#build-and-run)): chains to the embedded CAs or `--chain`, the signer's revocation by OCSP, intermediate CAs by CRL from `cRLDistributionPoints` (cached in `<data dir>/crl/`; a CRL is not downloaded again before its `nextUpdate`). `INDETERMINATE` means that everything checked is valid but no verdict is possible: revocation data is unavailable, or nothing proves when the signature was made.

### Deviations of P1 from the original

- Tokens (`AK…Store`) are unavailable until P14. File storages: `PKCS12` only in P1, `JKS` too (read-only) since P4.
- The original's password strength check for keys with EKU `1.2.398.3.3.4.2*` is not implemented in P1.
- `NCALAYERPORT` is honoured in any session; the original honours it only in RDP/Citrix/xrdp sessions. The value must be within `13579..=13679`.
- TLS 1.2 and 1.3; the original speaks only TLS 1.2.
- With `decode`, base64 in `data` is checked before the dialog is shown; the original checks it afterwards. The error code is the same.
- Key validity dates in the key dialog are shown in UTC, not local time.

### Deviations of P3 from the original

- When the CA set has several CAs with the same name (for example, a CA re-issued with the same subject and a new key), the chain goes through the one whose signature verifies. The original keeps CAs by DN, so the last CA of a name hides the others.
- The chain's anchor is checked like any CA: validity, `basicConstraints.cA`, `pathLen`, `keyCertSign`, unknown critical extensions. The original (Java PKIX) does not check the anchor.
- The OCSP status of all keys of a store is checked at once, within 6 s in total. The original checks the keys one after another, 5 s each. A key not checked within that time stays available, as on a network error.
- A key unavailable for another reason (EKU, IIN, BIN, serial number) is not checked with OCSP: the dialog shows those reasons. The original puts its «REVOKED» mark on such keys too.
- The dialog shows the revocation date, in UTC: «revoked DD.MM.YYYY». The original's mark has no date: «REVOKED».
- The OCSP responder is also found `byKey` (the SHA-1 of its key); the original understands only `byName`. A response's `thisUpdate` may be ahead of the computer's clock by up to 300 s; the original requires `thisUpdate < now` strictly.
- CRLs are checked only for intermediate CAs and only by `cms-verify` (the original's `basics` has no CRL). Delta CRLs and CRLs with an `issuingDistributionPoint` are refused. `ncagost`, `ncagost18`, `ncarsa` and `ncarsa18` have two CRL mirrors, `crl.root.gov.kz` and `crl1.root.gov.kz` (for `ncagost18` and `ncarsa18` in one string, `… URL=…`); OpenNCALayer tries both. At the time of checking (the date is in [`docs/dev/smoke-p3.md`](docs/dev/smoke-p3.md)) neither mirror served a current CRL for these CAs, and `cms-verify` reported their revocation status as unavailable.
- Certificate policies and `nameConstraints` are not checked in the chain (NCA certificates have no `nameConstraints`).

### Deviations of P4 from the original

#### XML signing

The points below are for `basics` (`format:"xml"`). commonUtils and the Applet sign with the same code: they keep the document's bytes, have the same input limits and refuse sha1RSA too, with error codes of their own.
- The document's bytes are kept, including the `<?xml …?>` declaration, whitespace and attribute order. The `ds:Signature` element is appended as the last child of the root element. The original re-serializes the document without the declaration (`omit-xml-declaration`). The signature verifies the same way, but the response string differs.
- Input limits the original does not have: at most 64 MiB and 256 levels of nesting, and bounded numbers of nodes, attributes and namespace declarations, as well as bounded canonicalization work. A document over the limits gets `UNABLE_TO_PARSE_XML`, like any parse error. The parse error text is ours; the original sends the SAX message.
- An attribute with a prefix and the local name `xmlns` (`a:xmlns`, `xml:xmlns`) is a parse error, `UNABLE_TO_PARSE_XML`. Our parser would take it for a default namespace declaration, while the original (Xerces) refuses `a:xmlns` with an undeclared prefix and takes `a:xmlns` with a declared prefix, and `xml:xmlns`, for ordinary attributes, so the signature would not match Kalkan's.
- A certificate signed with sha1RSA is not used for signing (`UNKNOWN_ALGORITHM`, as for cms). The original signs with rsa-sha1.
- A document with a comment or a processing instruction before the root element is signed. The original fails on it (`SIGNING_FAILURE`): it inserts the signature into the document's first node.

The XPaths of commonUtils `signXml` and `signXmls` are a subset: an absolute path of element names as written in the document (prefix included), each step with an optional `[n]`, `/` and `//` separators (`/root/body[2]`, `//data`), at most 32 steps. The prefix `SOAP-ENV` stands for the SOAP 1.1 namespace, as in Kalkan. An expression outside the subset gets `{"code":"500","message":"unsupported XPath expression \"…\""}`; a path of more than 32 steps gets `XPath expression "…" has more than 32 steps`. The original understands all of XPath 1.0.

#### Storages and page paths

The `JKS` (Java KeyStore) storage opens for signing in `basics` and `commonUtils`, read-only: no keys are written into it (`generateCsr` and `importCertificate` work with PKCS#12 only). RSA and GOST keys are read.

Paths a page names may not point to the network: the files of `createCAdESFromFile` and `createCMSSignatureFromFile`, the Applet module's key folders and files, the start folder of both modules' `showFileChooser`, and the `keystorePath` folder `importCertificate` puts into its dialog. UNC paths (`\\host\…`, `//host/…`, `\\?\UNC\…`; on Linux and macOS, paths starting with `//`) are refused before the file system is touched at all: otherwise the daemon would connect, without a dialog, to a host the page chose (on Windows, with the user's credentials). The exception is a network path the user chose in our file chooser (`showFileChooser` of both modules, the Applet's `browseKeyStore`) while the daemon runs, and the page got in the answer: the page may name that one, for example a `.p12` file or a key folder on a company share. Only that exact path is accepted, after the same lexical normalization (absolute; on Windows `/` read as `\`, `.` and `..` resolved), not its neighbours or the folder above it; the daemon remembers the last 64 such paths. The answer is the original's code for a file not found: `file.not_found` in commonUtils; in the Applet, `KEYSTORE_FILE_NOT_FOUND` (`setX509CertToKeyStore`), `CHANGEPASS_COMMON` (`changePassword`), `COMMON` (`genKeyPairAndGetPKCS10`). The Applet's `signXml` and `importCertificate` do not put such a path into their dialogs, and the folder or file chooser opens in its default folder. The original opens any path.

Tokens are not supported until P14 (see [Modules](#modules)).

#### `PKIEssentials`: `generateCsr` and `importCertificate`

- sha1RSA (`1.2.840.113549.1.1.5`) keys are not generated: `UNKNOWN_ALGORITHM` (the P1 rule against SHA-1). RSA of a length other than 2048, 3072 or 4096 bits is `UNKNOWN_ALGORITHM` too; the original generates RSA of any length.
- `params` are checked before the dialog: a bad entry or algorithm gets the original's code, but no dialog opens. The original shows the dialog first.
- One request creates at most 16 keys: more `params` entries give `INVOCATION_ERROR` with `java.lang.IllegalArgumentException: too many keys requested`, before the dialog. The original has no limit.
- Without `defaultPassword`, the `generateCsr` dialog asks for the key file password with a confirmation; the original's dialog cannot be confirmed in that case.
- Keys are only created in an existing folder given by an absolute path; otherwise `CSR_GENERATING_FAILURE`.
- The new password's pattern in `importCertificate` is checked before the first certificate is installed: on `WRONG_PASSWORD_PATTERN` no file changes. The original installs the certificate first.
- One `importCertificate` request installs at most 16 certificates: more `certificates` entries give `INVOCATION_ERROR` with `java.lang.IllegalArgumentException: too many certificates`, before the dialog. The original has no limit.
- `JKS` and tokens are listed in both dialogs but cannot be picked.
- Key files are written through a temporary file in the same folder. On Linux and macOS they get mode `0600`; on Windows the file gets the folder's permissions, and explicit permissions given to the old file are not kept.
- A key file path whose last component is `.` or `..` (on Windows `…\key.p12\a\..` opens `key.p12`) is not rewritten: an I/O error (`CERTIFICATE_IMPORTING_FAILURE`; in the Applet, the original's codes for a write failure, such as `CHANGEPASS_COMMON`). The original writes the file through such a path.

#### commonUtils

The `kz.gov.pki.knca.commonUtils` module:
- Tokens: as described in [Modules](#modules), which is also how the original answers with no device connected.
- `createCAdESFromFile` and `createCMSSignatureFromFile` show the full, normalized path of the file the page named in both dialogs. Only a regular file on disk of at most 64 MiB is read; a larger one gets `file.too_large: files over 64 MiB are not signed`. `file.not_found` goes to a folder and also: on Linux and macOS to FIFOs and devices; on Windows to device namespace paths (`\\.\…`, `\\?\…` except `\\?\C:\…` and `\\?\UNC\…`), named pipes, devices such as `NUL` and `CON`, and anything opened that is not a disk file. The original reads any path with no size limit.
- `getKeyInfo` opens the dialogs with the action "Key information" and a "Send" button, as the original does.
- The file chooser (`showFileChooser`) opens on top of other windows, in a small window naming the requesting site.
- A wrong password, and a store without keys of the requested `keyType`, reopen the storage dialog with an error (the no-keys texts are the original's). The original shows the error in its key dialog. Expired keys are available, as in the original, but the dialog does not mark them.
- Texts the original composes itself are the same: `action.canceled`, `storage.*`, `file.not_found`, `NoSuchMethodException …`, `UNKNOWN_ALGORITHM`, `CMS_NO_ENCAPSULATED_DATA`, `ISSUER_CERT_NOT_FOUND`, Kalkan's messages about the XML element, Java's base64 messages. XML and CMS parse errors, TSP and chain building errors are ours; a chain error follows the prefix `java.security.cert.CertPathBuilderException: `.
- An argument of the wrong type always gives `argument type mismatch`. After 15 calls of a method the original's JRE answers `java.lang.ClassCastException@<hash>` instead.
- `signXml` keeps the document's bytes, as `basics` does. An empty `signatureParentElementXPath` with a non-empty `tbsElementXPath` puts the signature into the root element; for the original it is an XPath error. A signature parent that is not found gets a message; the original answers without `message` (`NullPointerException`).

#### Applet

The `kz.gov.pki.knca.applet.Applet` module (legacy; it answers requests without a `module`):
- A subset is implemented for the file storages `PKCS12` and `JKS` (read-only): `showFileChooser`, `browseKeyStore`, `setPassword`, `getTryCount`, `genKeyPairAndGetPKCS10`, `setX509CertToKeyStore`, `setX509CertToKeyStoreAndChangePassword`, `changePassword`, `signXml`. `loadSlotList`, `getPublicPartInfo`, `deleteEntry` and `resetStorage` answer as the original does with no device. `genExt`, `getProvider`, `setProvider` and `showTokenChooser` answer `java.lang.NoSuchMethodException. Method: <name>`.
- Until P14 tokens answer `EMPTY_SLOT` (`browseKeyStore`: `TOKEN_CHOOSE_CANCEL`; `deleteEntry` and `resetStorage`: `COMMON`) and open no dialog. For a token, `changePassword` first checks the new PIN by the storage's rule, as the original does with no device: empty, or with characters or a length not allowed, gives `CHANGEPASS_INCORRECT_NEWPASS_PATTERN`; ID cards and the cloud storage give `UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION`; a valid PIN gives `CHANGEPASS_COMMON` (no device). `loadSlotList` always answers `EMPTY_SLOT`, also for `PKCS12` and an unknown name: the original checks the name only when a card is inserted.
- `genKeyPairAndGetPKCS10` generates GOST 34.310-2004 and sha256RSA keys of 2048, 3072 or 4096 bits, anything else is `GENKEY_UNKNOWN_ALG`. The original also generates sha1RSA, GammaTech GOST and RSA of any length (it does not generate GOST 2015 either). The key identifier is the original applet's: SHA-1 of the whole `SubjectPublicKeyInfo` (`generateCsr` hashes the public key's BIT STRING). It is the key file's alias, `localKeyId` and name, the request's SubjectKeyIdentifier and `secondResult`. Keys are created only in an existing folder given by an absolute path, local or a network folder the user chose in the file chooser, else `COMMON`; they are not written into `JKS` (`UNKNOWN_STORAGE_FOR_THE_CURRENT_OPERATION`). Values Kalkan writes unchecked give `GENKEY_COMMON`: a dNSName that is not ASCII (e.g. a Cyrillic CN with a non-empty `subjectAlternativeNames`), an `E` or `DC` that is not ASCII, a `SERIALNUMBER` or `C` with characters outside PrintableString. The original writes them mangled or as the wrong string type.
- One `genKeyPairAndGetPKCS10` request creates at most 16 keys: more `keyLengths` entries give `GENKEY_COMMON` before the first key is generated. The original creates, without a limit and without a dialog, as many key files as the page asks for.
- One `setX509CertToKeyStore` or `setX509CertToKeyStoreAndChangePassword` request installs at most 16 certificates: more certificates in the `<@>`-separated list give `SETCERT_COMMON` before any file is touched. The original rewrites a key file per certificate, without a limit and without a dialog.
- `setX509CertToKeyStore` checks the certificate first (SubjectKeyIdentifier, KeyStoreInfo: `SETCERT_COMMON`), then the folder, as the original does. It looks for the key in a folder only: a file or a missing path gives `SETCERT_COMMON`. The page names the folder, so at most 4096 of its entries are looked at and at most 64 key files (the first by name) tried; a key beyond these bounds gives `KEYSTORE_FILE_NOT_FOUND`. FIFOs and files over 64 MiB are skipped; this rule holds for `importCertificate` in `basics` too, but `importCertificate` searches the folder the user picks whole, as the original does. `JKS` gives `SETCERT_COMMON`. A key file with another password gives `KEYSTORE_FILE_NOT_FOUND`, as in the original, so `SETCERT_WRONG_PASSWORD`, `BLOCKED_KEYSTORE_PASSWORD` and `UNKNOWN_KNCA_CERTIFICATE_TYPE` never occur for files, in the original or here.
- `changePassword` and `signXml` read the key file by the commonUtils rules for page paths: a regular file on disk of at most 64 MiB only, local or chosen by the user in the file chooser (see above). A file the user picks in the `signXml` dialog is read by the same rules, but may be on any network share: only network paths the page names by itself are refused. `changePassword` reads the file once.
- `signXml` opens the storage dialog with the page's path (the user may pick another file), then the key dialog; there is no "Delete key" button. An empty password ("Empty field"), an `INAUTH`/`INSIGN` password outside the internal systems' policy (the original's texts), a wrong password, and a store without keys of the requested `keyType` reopen the storage dialog. A document that does not sign (e.g. not XML) keeps the key dialog open, showing the error; only cancelling closes it, with `SIGN_CANCEL`. The original's dialog stays open too, but shows no error. The document's bytes are kept, as in `basics`.
- The `setPassword` dialog shows the requesting site, and the page's text as plain text (the original renders it as HTML).

#### accessory

- `getBundles` lists the original's framework (`org.apache.felix.framework`) and its core bundles whose functions OpenNCALayer implements, with the versions of the original's current update manifest, and OpenNCALayer itself (`io.github.arynyklas.openncalayer`). The original lists every installed bundle, other vendors' modules included.
- `installBundle` with a non-empty `symname` and an `Origin` header always answers `BUNDLE_NOT_FOUND_OR_ALREADY_INSTALLED`, without a dialog: there are no ports of other vendors' modules until P11 (D21). For a module it can install, the original asks the user to confirm first. The request is logged; since P5 the OpenNCALayer icon also shows a notification linking to the plugin list `https://arynyklas.github.io/open-ncalayer/plugins/` (at most once in 10 minutes; the page itself arrives in P12). Without an `Origin` header the answer is `org.json.JSONException: JSONObject["origin"] is not a string.`, as from the original.
- `showBundleManager` opens the About window on its Modules tab, `showSettings` OpenNCALayer's settings window (the original's shows its proxy settings; OpenNCALayer's proxy is in the same window). `showKeystoreExplorer`, `showAdesSigning` and `showAdesValidation` open no window: the request is only logged. All five answer `{}`, as the original does.

## Desktop

### Tray icon

`openncalayer run` shows the OpenNCALayer icon (`tray-icon` on Windows and macOS, a StatusNotifierItem over D-Bus on Linux). Its menu:
- «Настройки…» (Settings…);
- «Сертификат для браузера…» (Browser certificate…) — the TLS wizard;
- «Журнал» (Log) — opens the `logs/` directory in the file manager;
- «О программе» (About);
- «Выход» (Quit) — stops the servers and ends the process. Closing a window does not end it.

The icon turns to "attention" when TLS is not set up, the server certificate expires within 60 days, or port 13579 is taken; its tooltip names the problem. When the original NCALayer holds the port, the menu gains «Остановить оригинал…» (Stop the original…; see [The original NCALayer](#the-original-ncalayer)). Notifications are a balloon of the icon on Windows, a desktop notification over D-Bus on Linux, and `osascript` on macOS. Menu and windows are in Russian, Kazakh or English.

`openncalayer run --no-tray` runs without the icon, as in P4 (end-to-end tests and sessions without a desktop use it). If the icon cannot be shown (Linux without StatusNotifier, a session without a notification area), a warning is logged and the daemon keeps serving and signing. On Linux a daemon started at login before the panel waits up to a minute for its StatusNotifierWatcher before it counts the icon as unavailable; a panel that appears later still gets the icon. What happens then with TLS not set up or a taken port is in [Build and run](#build-and-run).

### Settings

The settings window saves into `settings.json` of the data directory (other keys of the file, such as `recentPath`, are kept):
- `locale` — the language of the windows and the icon: `ru`, `kk` or `en`; without the key, the system's language if it is one of these three, else Russian;
- `autostart` — "start at login": our autostart entry `"<exe>" run` — the value `OpenNCALayer` of `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (Windows), `~/.config/autostart/openncalayer.desktop` (Linux), `~/Library/LaunchAgents/io.github.arynyklas.openncalayer.plist` with `RunAtLoad` (macOS). The window shows the entry's real state; an entry disabled in Task Manager → Startup counts as off;
- `proxy` — the proxy of time-stamping (TSP), OCSP and CRL requests: `{"mode":"none"}` (the default, direct connections as in P4), `{"mode":"system"}` (`ALL_PROXY`, `HTTPS_PROXY` or `HTTP_PROXY` with `NO_PROXY`, and without them on Windows the manual proxy of the Internet Options) or `{"mode":"manual","url":"http://host:port"}`. Plain HTTP goes to the proxy as an absolute-form request (`GET http://…`), HTTPS through a `CONNECT` tunnel. SOCKS and `https://` proxies are not supported. A new proxy applies at once, without a restart. The file may hold a proxy password, so on macOS and Linux only its owner can read it (mode `0600`).

The same window has:
- an "Original NCALayer" block: whether it is found, its autostart entries and their state, and the buttons «Отключить автозапуск оригинала» (Disable the original's autostart) and «Вернуть оригинал» (Restore the original);
- a "Browser extension" block: the `nm status` state and the buttons Register and Remove (the same as `openncalayer nm install` and `nm uninstall`).

### TLS wizard

The main way to set up the certificate is the «Сертификат для браузера…» wizard in the icon's menu; the `openncalayer tls init|import|status` commands remain. Details are in [`docs/user/tls.md`](docs/user/tls.md) (in Russian):
- **State** — the certificate, its validity, fingerprints and a read-only trust check (the Windows stores, the macOS keychain, NSS databases on Linux);
- **Source** — "create our own" (a local CA whose key is destroyed), "use mkcert", "own certificate (import)". The server takes a new certificate at once, without a restart;
- **Install** (D5) — OpenNCALayer never installs anything into a trust store by itself: only on a button press confirmed in the wizard's window. "Install my CA into the user's store" (Windows `CurrentUser\Root` — Windows shows its own warning; macOS — the login keychain; Linux — the checked NSS databases of Chrome and Firefox profiles through `certutil`; without it the wizard names the `libnss3-tools` package), "Remove" (exactly this CA, by fingerprint), "Download and install the NCA roots" (the embedded RSA certificates `rcarsa20` and `ncarsa22` after a SHA-256 check — for government sites with NCA TLS certificates) and "Remove the NCA roots" (exactly these two certificates), and "Remove the old one" after a re-issue;
- **Check** — "Open the check in the browser" opens `https://127.0.0.1:13579/openncalayer/selftest`; browsers that open the page appear in the wizard's list.

mkcert: the CA is looked up in `$CAROOT` or the `mkcert -CAROOT` directory. It needs consent (a checkbox): the key `rootCA-key.pem` is read at every issue but never copied. Unchecking withdraws the consent. With consent the server certificate (at most 800 days) re-issues itself 30 days before it expires — at start and once a day, and only with the mkcert CA that issued the certificate in use; if the key is unavailable or has changed, or the mkcert CA has changed (the new one's key is then not read), the previous certificate keeps working and a notification names the reason.

Reminders: at start and once a day OpenNCALayer checks the server certificate's expiry; 60 days before it, the icon turns to "attention" and a notification leads to the wizard.

### The original NCALayer

The original and OpenNCALayer cannot both serve `wss` at the same time: both need port 13579.

«Остановить оригинал…» appears in the icon's menu when the original holds the port (`NCALayer.exe`, `ncalayer.sh` or Java with `ncalayer` in its command line; the port's owner is found with `GetExtendedTcpTable` on Windows, `/proc` on Linux, `lsof` on macOS). A window shows the program and its process id; after "Stop" OpenNCALayer checks once more that it is the same process (path and start time), ends it and starts wss in the running daemon. No other process is ever ended.

«Отключить автозапуск оригинала» (D13) deletes nothing:
- Windows — the shortcut `NCALayer.lnk` in the user's Startup folder, and any other shortcut there to `NCALayer.exe` (a localized name), move to `original-autostart/` in the data directory;
- Linux — `~/.config/autostart/ncalayer.desktop` gets `Hidden=true`, with a copy of the previous file in `original-autostart/`;
- macOS — the original has no autostart; the window says "not found".

The value `NCALayer` of `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` (also in the 32-bit view, `WOW6432Node`), written by the original's MSI, is only shown: only an administrator can turn it off, and the window says how. Entries the user turned off (for example in Task Manager) are left alone.

«Вернуть оригинал» puts the moved shortcuts and `ncalayer.desktop` back and turns our autostart off. Both actions keep the journal `original-autostart.json` in the data directory: an entry is written before a change and removed only after it is put back, so an interrupted action is finished by pressing the button again, and nothing is lost.

### About

The About window: version, build commit, the Apache-2.0 licence, `Copyright 2026 Aryn Yklas`, a link to the repository and the mandatory `AboutSlint` element; a Modules tab (the bundles of `getBundles` and the daemon's modules); a third-party licences tab — the text of `crates/oncl-ui/assets/THIRD-PARTY.txt`, written by `cargo xtask licenses` (`cargo xtask licenses --check` checks that it is current).

### P5 differences from the original

- `showSettings` opens OpenNCALayer's settings (language, autostart, proxy, the original, the extension), not the original's proxy window; `showBundleManager` a list of modules without install or removal.
- `installBundle` installs no third-party modules (D21): the icon shows a notification linking to the plugin list.
- Proxy: no SOCKS and no `https://` proxies; no proxy by default, even if the system has one.
- The certificate for `wss` is issued on the user's computer and installed into trust stores only by a wizard button (D5); the original ships its own certificate.
- The original's autostart is disabled by moving it aside, not deleting it; `HKLM\…\Run` is not changed without administrator rights.

## Ready-made builds

[Releases](https://github.com/arynyklas/open-ncalayer/releases): archives for Windows x64 and x86 (`x86_64-pc-windows-msvc`, `i686-pc-windows-msvc`), Windows 7 SP1 x64 and x86 (`win7-x64`, `win7-x86`; they carry `combase.dll` and `api-ms-win-core-winrt-error-l1-1-0.dll` next to the programs, keep them in one folder), Linux x64 (`x86_64-unknown-linux-gnu`, built on Ubuntu 24.04) and macOS on Apple Silicon (`aarch64-apple-darwin`) with `openncalayer` and `nmhost`, the extensions `openncalayer-chromium-<version>.zip` and `openncalayer-firefox-<version>.xpi` (unsigned: Firefox installs it only temporarily), and `SHA256SUMS`. Versions with a suffix (`0.1.0-alpha.1`) are pre-releases. The binaries are not code-signed: Windows SmartScreen and macOS Gatekeeper warn on first start. A `v<version>` tag builds and publishes the release by itself (`.github/workflows/release.yml`).

Unpack the archive and go on as with your own build: `openncalayer run`, and the extension as in [Browser extension](#browser-extension).

## Windows 7

Windows 7 SP1 has archives of its own: `openncalayer-<version>-win7-x64.zip` (64-bit system) and `openncalayer-<version>-win7-x86.zip` (32-bit). On Windows 10 and 11 take the regular `openncalayer-<version>-x86_64-pc-windows-msvc.zip` and `openncalayer-<version>-i686-pc-windows-msvc.zip` (x86). The Windows 7 builds link the CRT statically: no Visual C++ Redistributable is needed.

The Windows 7 archive has two small DLLs next to `openncalayer.exe` and `nmhost.exe`. Unpack the whole archive and keep them in the program's folder:
- `combase.dll` forwards `CoTaskMemFree` and `CoCreateFreeThreadedMarshaler` to `ole32.dll`. The `windows` crates behind the windows (Slint and its dependencies) import these functions from `combase.dll`, which Windows 7 does not have;
- `api-ms-win-core-winrt-error-l1-1-0.dll` holds stubs of `RoOriginateErrorW` and `RoOriginateError`: Windows 7 has no WinRT to report an error to, so they do nothing and return `FALSE`.

The DLLs export only these functions and reach only `kernel32.dll` and `ole32.dll`. On Windows 8 and later neither DLL is loaded: `combase.dll` is a KnownDLL there and `api-ms-…` an API set, so the loader takes the system ones. The Windows 7 build therefore also runs on newer Windows: its start was checked on Windows 11; the CI job `win7` checks it on Windows Server 2025, but that job has not run yet; Windows 10 has not been checked. The relay `nmhost.exe` does not need the DLLs: `nm install` copies it on its own.

On Windows 7 the windows take their default font size from the system metrics (`SystemParametersInfoW`), scaled for DPI: `SystemParametersInfoForDpi`, which Slint uses, does not exist on Windows 7 (details in [Development](#development)).

Browsers on Windows 7: Firefox ESR 115 and Chrome 109 are the last versions for it. The extension installs into Firefox ESR 115 just as into regular Firefox (see [Browser extension](#browser-extension)). There the shim works through Xray vision, which has limits of its own: a page subclass of `WebSocket` does not get its own class for any URL (in other browsers only for NCALayer URLs), and open tabs must be reloaded after the extension is disabled, removed or updated (see [Deviations and limits of the extension](#deviations-and-limits-of-the-extension-p2)). The end-to-end extension test passes in Firefox ESR 115 on Linux.

Not checked yet: no real Windows 7 has run these builds; Windows 7 VMs come with the lab (P9). Checked automatically: every import (the import gate: no DLL or function from the Windows 8+ list) and starting the build on Windows 11. Not checked: start and tray icon on Windows 7, the signing window and its font, the eGov login through the extension in Firefox ESR 115 and Chrome 109, and matching the imports against the full Windows 7 SP1 export list. The checklist is in [`docs/dev/smoke-p6.md`](docs/dev/smoke-p6.md) (in Russian).

## Build and run

You need `rustup`: the Rust version is pinned in `rust-toolchain.toml` and installed automatically. On Linux the dialogs need the fontconfig, xkbcommon, Wayland and GTK 3 development packages (Debian and Ubuntu: `libfontconfig1-dev libxkbcommon-dev libwayland-dev libgtk-3-dev`).

To run on Linux you also need:
- `libxkbcommon-x11-0`: without it the signing dialogs cannot open and `openncalayer run` exits with an error (`libxkbcommon-dev` does not install it);
- `xdg-desktop-portal` with a backend (for example `xdg-desktop-portal-gtk`) or `zenity` for the «Обзор…» (Browse) button; without them the system file dialog does not open (the log has the rfd error), and the key file path can still be typed in.

```sh
cargo build --release -p openncalayer
```

The binary is `target/release/openncalayer` (`openncalayer.exe` on Windows).

The main way is the «Сертификат для браузера…» wizard in the icon's menu (see [TLS wizard](#tls-wizard)). From the command line:

```sh
openncalayer tls init   # issue the certificate and print how to trust the CA
openncalayer run        # start the server with the icon; plain `openncalayer` does the same
```

1. Issue the certificate in the wizard or with `tls init`, and trust the CA with the wizard's button or as the printed instructions say. Per-OS details are in [`docs/user/tls.md`](docs/user/tls.md).
2. Start `openncalayer run` and open `https://127.0.0.1:13579/`: the page must load without a certificate warning.
3. At `https://127.0.0.1:13579/demo/` you can sign a text or a file and download the `.p7s`.
4. To check a signature: `openncalayer cms-verify signature.p7s`; for a detached signature, `openncalayer cms-verify signature.p7s --content <data file>`. It checks the signatures and timestamps, the certificate chains of the signer and of the TSA through the embedded NCA certificates (`--chain <CA file>` replaces them; repeatable, and a PEM file may hold several certificates), validity periods and revocation: the signer by OCSP, intermediate CAs by CRL (cached in `crl/` of the data directory). Only a verified timestamp proves when the signature was made: validity and revocation are judged at its `genTime`, and without one at the current time; `signingTime` is the signer's own claim and is only printed. A revocation after the timestamp does not invalidate the signature: `OK` comes with the line `revocation: revoked … after signing (…)`. The last line is `OK`, `FAIL: <reason>`, `INDETERMINATE: revocation data unavailable` (everything else holds, but no revocation data could be obtained) or `INDETERMINATE: no proof of signing time` (the certificate is expired or revoked now, and the signature would only hold at the claimed `signingTime`). The exit code is 0 only for `OK`. With `--offline` revocation is not checked and the line `not checked: revocation` precedes `OK`.

Exit codes of `run`:
- 2 — TLS is not set up;
- 3 — the port is taken, for example by the original NCALayer;
- 4 — OpenNCALayer with the same data directory is already running in this session.

Codes 2 and 3 occur only without the icon: `--no-tray`, an icon not shown, one lost on the event loop's first turn (macOS), or one that no StatusNotifierWatcher took within a minute of the start (Linux). Even then they occur only while wss is still off; a daemon whose problem was fixed by then (the original stopped from the notification, a certificate saved) keeps serving without the icon. With the icon, `run` keeps serving the extension when TLS is not set up or the port is taken, the icon shows the problem, and wss starts in the same process once the wizard saves a certificate or the port is free. A daemon started by the user or by our autostart notifies at start and takes a freed port by itself (it checks every 30 seconds).

With `--allow-no-wss` (how the extension's relay starts the daemon) no wss startup failure (codes 2, 3 and 1) stops the daemon: it logs a warning and serves only the extension. Such a daemon does not take a freed port by itself: it starts wss only after a user action in the tray or the TLS wizard (stopping the original, saving a certificate).

The original and OpenNCALayer cannot both serve `wss` at the same time: both need port 13579. The extension does not need the port.

Data lives in `%APPDATA%\OpenNCALayer` (Windows), `~/Library/Application Support/OpenNCALayer` (macOS) or `${XDG_DATA_HOME:-~/.local/share}/openncalayer` (Linux). Inside:
- `tls/` — certificates;
- `logs/openncalayer.YYYY-MM-DD.log` — logs, a new file every day;
- `settings.json` — the settings (`locale`, `autostart`, `proxy`) and the path of the last chosen key file;
- `original-autostart.json` and `original-autostart/` — the journal and the moved autostart entries of the original.

The `ONCL_DATA_DIR` variable overrides the data directory. Set it during development (for example `ONCL_DATA_DIR=target/oncl-data`) so your real profile stays untouched.

## Browser extension

The extension replaces a page's `WebSocket` to `127.0.0.1`, `localhost` and `[::1]` on ports 13579–13679 and passes the messages to OpenNCALayer over native messaging. The browser starts a small relay, `nmhost`, and the relay starts the daemon (`openncalayer run --allow-no-wss`) unless it is already running. This path needs neither the certificate nor port 13579: `wss` and a trusted CA are now needed only for sites in browsers without the extension.

There are no packages yet; build the extension from source:

```sh
cargo build --release -p openncalayer -p oncl-nmhost
cargo xtask ext build   # → target/extension/
```

`ext build` writes the unpacked extensions `chromium/` and `firefox/` to `target/extension/`, next to `openncalayer-chromium-<version>.zip` and the unsigned `openncalayer-firefox-<version>.xpi`.

Installation:
1. `openncalayer nm install` registers the native messaging host `io.github.arynyklas.openncalayer`:
   - copies the `nmhost` relay (by default the one next to `openncalayer`; another file with `--relay <file>`) to `%LOCALAPPDATA%\OpenNCALayer\nmhost.exe` (Windows) or into the data directory (macOS, Linux);
   - writes `nmhost.json` next to it with the absolute paths of the data directory and the `openncalayer` binary;
   - writes the host manifests: on macOS and Linux for the browsers it finds (Chrome, Chromium, Edge, Brave, Yandex Browser, Firefox); on Windows always `%LOCALAPPDATA%\OpenNCALayer\nm\{chromium,firefox}.json` and the keys `HKCU\Software\{Google\Chrome,Chromium,Microsoft\Edge,Mozilla}\NativeMessagingHosts\io.github.arynyklas.openncalayer`.

   The command never touches certificates. Check with `openncalayer nm status` (exit code 1 if anything is missing); remove with `openncalayer nm uninstall` (the data directory stays).
2. Chrome, Edge, Yandex Browser: the extensions page (`chrome://extensions`, `edge://extensions`) → "Developer mode" → "Load unpacked" → the `target/extension/chromium` directory or the unpacked `openncalayer-chromium-<version>.zip`. The extension id must be `cmdaoegbcpdhoamhgmibpgpnlojopcal`: the host accepts no other id.
3. Firefox (115 or later, ESR 115 included — the last Firefox for Windows 7): for now only a temporary install — `about:debugging` → "This Firefox" → "Load Temporary Add-on…" → `target/extension/firefox/manifest.json`; the add-on is gone after a Firefox restart. Only an AMO-signed (unlisted) XPI installs permanently: Firefox refuses the unsigned `.xpi`.
4. Reload the open tabs of the sites.

Good to know:
- `nm install` resolves the data directory like `run` does, honouring `ONCL_DATA_DIR`. After moving the `openncalayer` binary or changing the data directory, run `nm install` again.
- A repeated `nm install` replaces the relay by renaming: relays the browser is running keep working with the old file. Old `nmhost.old-*` files are removed by the next `nm install`. On Windows `nm uninstall` cannot delete a relay the browser is holding (the relay line says «занят запущенным процессом», exit code 1): close the browser and run the command again. On macOS and Linux the file is removed at once.
- A daemon started by the relay runs until the session ends. If TLS is set up and port 13579 is free, the same daemon serves `wss` too; otherwise the log has a warning and the daemon serves only the extension until the user stops the original or saves a certificate in the wizard.
- Through the extension, the site origin that modules see comes from the browser, not from the page.
- If the host is not installed or the daemon does not start, the extension gives the page its own `WebSocket`, i.e. the original NCALayer if it is running. While the host is installed, sites go to OpenNCALayer even when the original is running. To return to the original, run `nm uninstall` and restart the browser (or stop the daemon), or disable the extension: right after `nm uninstall` the browser keeps using the relay and daemon already running. After the extension is disabled, open tabs in Chromium and Firefox 128 or later switch to the page's own `WebSocket` by themselves, but only for new sockets and `fetch`; in Firefox ESR 115 they must be reloaded (see below). A socket already open through the extension does not switch to the original: in Firefox 128 or later, on its next `send` the page gets `error` and `close` with code 1006 (like the browser, from a later task, not from inside `send`), and the pending request fails; a socket that only waits for messages gets nothing and stays open until the page closes it or uses NCALayer again (a new socket, `fetch` or `send`). In Chromium the end-to-end test does not check this.
- Firefox before 128 (ESR 115) has no `world: "MAIN"` for content scripts. There the shim runs as an ordinary content script: it replaces the page's `WebSocket` and `fetch` through Xray vision (`window.wrappedJSObject`, `exportFunction`, `cloneInto`) and hands frames to the bridge directly, with no events on `document`. In Firefox 128 and later the shim runs in the page's world, as in Chromium.
- Firefox ESR 115: after disabling, removing, reloading or updating the extension, reload the open tabs. Until then `WebSocket` and `fetch` in them throw `TypeError: can't access dead object` — on every site, not only NCALayer ones. Firefox destroys the content script together with the functions it gave the page, and lets it run nothing before that.

Linux, Firefox from snap and Flatpak:
- `nm install` detects Firefox by `~/.mozilla` or `~/.config/mozilla`. Snap Firefox keeps its profile under `~/snap/firefox/`, so the command may skip Firefox ("пропущен"). Then create the directory with `mkdir -p ~/.mozilla` and run `nm install` again: the manifest goes to `~/.mozilla/native-messaging-hosts/`, where snap Firefox 135 or later reads it through xdg-desktop-portal.
- Flatpak Firefox starts native messaging hosts only through `xdg-native-messaging-proxy` on the host system. OpenNCALayer neither installs it nor changes Flatpak permissions: set this up by hand.
- Neither has been tested.

### Deviations and limits of the extension (P2)

- A page's subclass of `WebSocket` (`class X extends WebSocket`) creates a plain `WebSocket`, not an `X`, for an NCALayer URL in every browser: the extension makes that socket. In Firefox ESR 115 the same holds for any other URL: Firefox constructs a function a content script gave the page with that function itself as `new.target`, so the page's class never reaches the shim.
- In Firefox ESR 115, open tabs must be reloaded after the extension is disabled, removed or updated: until then `WebSocket` and `fetch` do not work in them.
- Chrome 109 (the last Chrome for Windows 7) is the declared minimum but has not been tested.
- Safari is not supported.
- Sockets a site opens from a Web Worker are not replaced: they still need `wss` and the CA.
- Through the extension, one tab holds at most 256 open sockets and all tabs of a profile together at most 4096 (the daemon's limit). A socket over the limit is closed at once with code 1006, like a refused connection.
- The native messaging paths of Yandex Browser and Opera are untested. On Windows they read Chrome's registry key; on Linux the Yandex Browser manifest goes to `~/.config/yandex-browser/NativeMessagingHosts/`.

## Development

```sh
cargo build --workspace
cargo xtask fetch-fixtures   # NCANode test data → target/fixtures/ncanode/
cargo test --workspace --all-features
```

`cargo xtask fetch-fixtures` downloads [NCANode](https://github.com/ncanode-kz/NCANode) test files from a pinned commit and verifies their sha256. These files are never committed. A repeated run downloads nothing when the files are already in place.

The test keys in `fixtures/synthetic/` are synthetic, password `Qwerty12`. They work on the demo page. By default the demo sends `chain: []`, so synthetic and NCANode test keys are available. The «synthetic test root» choice sends `root-gost2015`: keys of the other roots and of the intermediate CA become unavailable.

Tests prefixed with `live_` call real NCA services and are skipped by default:

```sh
cargo test --workspace --all-features -- --ignored live_
```

They are `live_test_tsa` (the NCA test TSP), `live_ocsp_nca_test_certificate` (the NCA test OCSP responder; needs `cargo xtask fetch-fixtures`), `live_crl_nca_root_gost_2022` (a CRL from the production `crl.root.gov.kz`) and `live_cms_verify_command_without_revocation_services` (`cms-verify` with nonexistent OCSP and CRL hosts; needs only DNS). They depend on outside services, so CI runs them only on a schedule and on demand (`workflow_dispatch`, the `live` job), and a single network failure is worth a rerun. The NCA test RSA OCSP responder answers `malformedRequest` to standard requests (OpenSSL's too), so live OCSP is tested with a GOST certificate.

The browser extension:

```sh
node --test "extension/test/*.test.mjs"   # extension tests, Node 22 or later
cargo xtask ext build                     # → target/extension/
```

End-to-end check of the extension in Chrome for Testing, Firefox and Firefox ESR 115 (Linux only; browsers and drivers are downloaded to `target/browsers/`):

```sh
cargo build --release -p openncalayer --features e2e-prompter -p oncl-nmhost
cargo xtask ext build
cargo xtask ext-e2e --download
```

Without `--download` the paths come from `ONCL_CHROME`, `ONCL_CHROMEDRIVER`, `ONCL_FIREFOX`, `ONCL_FIREFOX_ESR` and `ONCL_GECKODRIVER`; one browser only: `--browser chromium|firefox|firefox-esr`. Firefox ESR 115 needs the system library `libdbus-glib-1-2`. The browsers run with throwaway profiles in `target/ext-e2e/`, and the host is registered there too (`nm install --sandbox`). The `e2e-prompter` feature replaces the signing dialogs with a script from the `ONCL_E2E_PROMPTER` file; regular builds do not have it. Scenario 8 removes the extension under an open page (Firefox only; in ESR 115 it checks the limitation described above).

Windows 7 SP1 builds (on Windows only, with the pinned nightly):

```sh
rustup toolchain install nightly-2026-08-12 --profile minimal --component rust-src
cargo xtask win7 --arch all   # → target/win7/x64/, target/win7/x86/
```

`cargo xtask win7` builds `openncalayer.exe` and `nmhost.exe` for `x86_64-win7-windows-msvc` and `i686-win7-windows-msvc` (`-Zbuild-std`, static CRT: no VC++ redistributable needed) and puts two DLLs Windows 7 lacks next to them: `combase.dll` forwards `CoTaskMemFree` and `CoCreateFreeThreadedMarshaler` to `ole32.dll`, and in `api-ms-win-core-winrt-error-l1-1-0.dll` the functions `RoOriginateErrorW` and `RoOriginateError` do nothing. Windows 8 and later never load these copies: there `combase.dll` is a known DLL, and `api-ms-win-*` names resolve through the API set schema.

Then the import gate runs, also available as `cargo xtask check-imports <exe>…`:
- an import from a DLL or of a function on the list of those known to be missing on Windows 7 fails (decorated x86 names too). This is a denylist: a Windows 8+ import outside it passes; matching against the Windows 7 SP1 exports (an allowlist) comes with the lab (P9);
- an import from `combase.dll` or `api-ms-win-core-winrt-error-l1-1-0.dll` passes only if the DLL of that name lies next to the exe and exports exactly that name; a new import such as `combase!CoTaskMemAlloc` fails until the DLL exports it;
- these DLLs have the exe's bitness and import from and forward to `kernel32.dll` and `ole32.dll` only, by undecorated name;
- `nmhost.exe` must do without them: `nm install` copies the relay apart from the program.

On Windows, `cargo xtask win7` then starts the build from `target/win7/<arch>/`: `--help`, `nm install` and `nm status` in a sandbox, `tls init`, then `run` until it answers `GET /` over HTTPS, with the data directory in a temporary directory under `target/win7-smoke/`. In CI this is the blocking `win7` job (x64 and x86 on Windows Server 2025; it has not run yet); checks on Windows 7 itself come with the lab (P9).

Before submitting changes:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check
cargo xtask licenses --check   # the About window's third-party licences are current
```

`web/demo/vendor/ncalayer-client.js` is `package/ncalayer-client.js` from the npm package `ncalayer-js-client@1.6.1`, unmodified (MIT, sha256 `bdf2015c3e422eed70ccf38eef3246af67a0d38639e6b70fe6b8655a2fa03489`). The `demo_assets_served` test checks the sha256 of the file the server sends. The server sends the client's license next to it: `/demo/vendor/LICENSE`.

`vendor/i-slint-backend-winit` is the crates.io package `i-slint-backend-winit` 1.18.1 (Slint's winit backend), modified, in the build through `[patch.crates-io]`. One place changed: the default font size on Windows (`windows_message_font_height` in `lib.rs`, called from `bind_context`). `SystemParametersInfoForDpi` (Windows 10 1607 and later) is looked up with `GetProcAddress`; without it, `SystemParametersInfoW(SPI_GETNONCLIENTMETRICS)` is called and the height is scaled from the system DPI to 96. `Cargo.toml` adds the `Win32_System_LibraryLoader` feature of `windows`. So the Windows 7 builds do not import a function Windows 7 lacks, and Windows 10/11 make the same call as before. Slint's royalty-free license 2.0 allows modifying the software and distributing it modified as part of an application (sections 1–2); the license notices in the files are kept. The `locked_slint_winit_backend_is_the_patched_copy` test fails if a Slint upgrade leaves the patch unused; on an upgrade, replace the copy with the new package and carry the change over.

## License

© 2026 Aryn Yklas.

[Apache-2.0](LICENSE); see also [NOTICE](NOTICE). `web/demo/vendor/ncalayer-client.js` is MIT, see [`web/demo/vendor/LICENSE`](web/demo/vendor/LICENSE). `vendor/i-slint-backend-winit` is a modified copy of Slint's winit backend, used under LicenseRef-Slint-Royalty-free-2.0, see [`vendor/i-slint-backend-winit/LICENSES`](vendor/i-slint-backend-winit/LICENSES).
