//! The OpenNCALayer port of `kz.gov.pki.eot.SignModule` 1.0 (E-Otinish), the module
//! `kz.gov.pki.eot.SignModule`: the reflective dispatcher over
//! `kz.gov.pki.eot.signmodule.EotSignerModuleService` with one public method,
//! `signCmsWithSignedAttrs` — a detached ESEDO CMS whose messageDigest is the page's bytes
//! (a digest it computed), with the file names, the signer's DN, `ESEDO`, an OCSP answer
//! taken before signing and a time-stamp of Kalkan's default profile.

#[cfg(target_arch = "wasm32")]
mod port {
    use oncl_pdk::abi::{
        CmsCerts, CmsOutcome, CoSign, HashAlg, MAX_PKI_TIMEOUT_MS, Nonce, OcspOutcome, PkiMethod,
        TimeForm, TsaChoice,
    };
    use oncl_pdk::keys::{Action, Filter, KeyOrder};
    use oncl_pdk::legacy::{
        self, Args, ErrorBean, LegacyBody, LegacyClass, LegacyMethod, Outcome, Param,
    };
    use oncl_pdk::{AddInfo, Request, host, javab64, pki};
    use oncl_port_legacy::{
        ACTION_CANCELED, Select, UNKNOWN_ALGORITHM, base64, fail, into_text, knca_types,
        net_exception, net_message, ok, select, split_names,
    };
    use oncl_port_pki::esedo::{
        CertIdHash, ContentMode, Description, Encapsulate, EsedoInput, FileNames, IssuerRule,
        OcspAnswer, OcspForm, OcspRequest, OcspUrl, Profile, SignerDn, SigningTimeRule, StringKind,
        TimeFrom, ocsp_args, sign_args,
    };

    /// The CA certificate the original bundles and names as the issuer of every OCSP
    /// request: the NCA's GOST CA of 2022.
    const NCA_GOST_2022: &[u8] = include_bytes!("../../../fixtures/nca/prod/ncagost22.der");

    /// The module's CMS: detached, messageDigest the page's bytes, the signer certificate;
    /// contentType, signingCertificateV2, signingTime (UTCTime, now), the file names joined
    /// by `<>` (always, empty without names), the signer's DN from Kalkan's DN text,
    /// signingDescription PrintableString `ESEDO` and OCTET STRING { BasicOCSPResponse }.
    pub const EOT: Profile = Profile {
        econtent_type: None,
        content: ContentMode::Digest,
        digest: None,
        encapsulate: Encapsulate::Never,
        cosign: CoSign::Never,
        certificates: CmsCerts::Signer,
        content_type: true,
        signing_certificate_v2: true,
        signing_time: Some(SigningTimeRule {
            from: TimeFrom::Now,
            form: TimeForm::Utc,
        }),
        file_names: Some(FileNames {
            separator: "<>",
            omit_blank: false,
        }),
        signer_dn: Some(SignerDn::Kalkan),
        description: Some(Description {
            text: "ESEDO",
            kind: StringKind::Printable,
        }),
        ocsp: Some(OcspForm::OctetBasic),
        ocsp_request: Some(EOT_OCSP),
    };

    /// The OCSP request before signing: the given issuer, a SHA-1 `CertID`, an 8-byte
    /// nonce, POST to `http://ocsp.pki.gov.kz/<request>` with the request as the body too;
    /// the status is not checked.
    pub const EOT_OCSP: OcspRequest = OcspRequest {
        issuer: IssuerRule::Given,
        cert_id_hash: CertIdHash::Fixed(HashAlg::Sha1),
        nonce: Nonce::Random(8),
        method: PkiMethod::PostWithPath,
        url: OcspUrl::Default,
        // The original waited without a limit.
        timeout_ms: MAX_PKI_TIMEOUT_MS,
        check: false,
    };

    /// The module's state: none.
    pub struct Service;

    use Param::{Bool, Str};

    const METHODS: &[LegacyMethod<Service>] = &[
        LegacyMethod {
            name: "signCmsWithSignedAttrs",
            arity: 5,
            body: LegacyBody::Public(&[Str, Str, Str, Bool, Str], sign_cms_with_signed_attrs),
        },
        LegacyMethod {
            name: "getJson",
            arity: 1,
            body: LegacyBody::PrivateTakingObject,
        },
    ];

    const CLASS: LegacyClass<Service> = LegacyClass {
        dispatcher: "kz.gov.pki.eot.signmodule.Activator",
        target: "kz.gov.pki.eot.signmodule.EotSignerModuleService",
        methods: METHODS,
        error_bean: ErrorBean::ResponseMessage,
        no_such_method: legacy::no_such_method_exception,
        before_invoke: None,
    };

    /// The plugin's handler.
    pub fn handle(request: &Request) -> String {
        into_text(legacy::dispatch(
            &Service,
            &CLASS,
            &request.text,
            &request.add_info(),
        ))
    }

    /// `signCmsWithSignedAttrs(storageName, keyTypeValue, base64ToSign, flag, fileNames)`:
    /// `flag` is read and ignored (the CMS is always detached).
    fn sign_cms_with_signed_attrs(_: &Service, args: &Args<'_>, _: &AddInfo) -> Outcome {
        match sign(args.str(0), args.str(1), args.str(2), args.str(4)) {
            Ok(cms) => ok(base64(&cms)),
            Err(message) => fail(Some(&message)),
        }
    }

    fn sign(
        storage: &str,
        key_type: &str,
        data: &str,
        file_names: &str,
    ) -> Result<Vec<u8>, String> {
        let names = split_names(file_names);
        // The old StorageInfo (no recent keys) and a key dialog listing the oldest first.
        let key = select(Select {
            storage,
            action: Action::Sign,
            knca_types: knca_types(key_type),
            order: KeyOrder::OldestFirst,
            filter: Filter {
                allow_expired: true,
                chain: Some(Vec::new()),
                allow_revoked: true,
                ..Filter::default()
            },
        })?
        .ok_or_else(|| ACTION_CANCELED.to_owned())?;
        let data = javab64::decode_java(data)?;
        let cert = key.certificate();
        let details = host::cert_details(cert).map_err(|e| e.message)?;
        // The digest by the certificate; the core makes no SHA-1 RSA signature, and the
        // original knows no GOST 2015-256.
        let rsa = match details.signing_alg.as_deref() {
            Some("rsa_sha256") => true,
            Some("gost2004" | "gost2015_512") => false,
            _ => return Err(UNKNOWN_ALGORITHM.to_owned()),
        };
        // The original names its bundled GOST CA as the issuer for every key; an RSA key
        // gets its real issuer from the core's CAs (the GOST CA does not issue it).
        let issuer = match rsa {
            true => host::ca_issuer(cert)
                .map_err(|e| e.message)?
                .unwrap_or_else(|| NCA_GOST_2022.to_vec()),
            false => NCA_GOST_2022.to_vec(),
        };
        let request = ocsp_args(&EOT_OCSP, cert, &[&issuer])?;
        let outcome = pki::ocsp_fetch(&request).map_err(|e| e.message)?;
        match &outcome {
            OcspOutcome::Failed(failure) => return Err(net_message(failure)),
            // Unverified against the original: the text of the response object, which an
            // unsuccessful OCSPResponse does not have (`null`).
            OcspOutcome::Ok {
                response_status, ..
            } if *response_status != 0 => {
                return Err(format!(
                    "OSCP Response Unsuccessfull: {response_status} reason: null"
                ));
            }
            OcspOutcome::Ok { .. } => {}
        }
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        let input = EsedoInput {
            cert,
            kalkan_dn: Some(&details.subject_dn),
            file_names: &names,
            ocsp: OcspAnswer::from_outcome(&outcome),
            data: &data,
            ..EsedoInput::default()
        };
        let mut args = sign_args(&EOT, &input, key.handle())?;
        args.timestamp = Some(TsaChoice::Kalkan);
        match key.sign_cms_ex(args) {
            Ok(CmsOutcome::Signed(cms)) => Ok(cms.into_vec()),
            // Kalkan's ProviderUtilException carries the cause's `toString()`.
            // Unverified against the original: the message of a failed time-stamp.
            Ok(CmsOutcome::TspFailed(failure)) => Err(net_exception(&failure)),
            Err(e) => Err(e.message),
        }
    }
}

#[cfg(target_arch = "wasm32")]
oncl_pdk::plugin!(port::handle);
