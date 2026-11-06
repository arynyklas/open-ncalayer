//! OpenAPI 3.1 description of the implemented `/v1` contract. Request examples
//! are parsed with the real metadata DTOs and response examples are serialized
//! from the real result DTOs, so the published examples cannot drift from the
//! wire types. No example carries key material or a usable token.
use crate::{
    dto::{
        BatchItemOutcome, BatchItemRecord, BatchStatus, BatchStop, BatchStopKind, FinalStatus,
        HashAlgorithm, InspectedCms, InspectedEntry, ItemResult, JwsSignerFacts, OperationMetadata,
        OperationResult, ResponseEvent, SignKind, SignerChecks, SourceIdentity, TimestampFacts,
        VerifyProfile,
    },
    error::{ApiError, AppliedState, ErrorCode},
};
use serde_json::{Value, json};

const HASH_EXAMPLE: &str = r#"{"items":[{"id":"h1","operation":{"kind":"hash","algorithm":"sha256","input":"doc"}}],"parts":[{"name":"doc","item_id":"h1","role":"document"}]}"#;
const VERIFY_EXAMPLE: &str = r#"{"items":[{"id":"v1","operation":{"kind":"verify","profile":"cades_t","input":"signature","detached":"content"}}],"parts":[{"name":"signature","item_id":"v1","role":"document"},{"name":"content","item_id":"v1","role":"document"}]}"#;
const SIGN_EXAMPLE: &str = r#"{"items":[{"id":"s1","operation":{"kind":"sign","profile":"cades_b","input":"doc","attached":false,"keys":[{"source":"inline","container":"key","password":"pin"}]}}],"parts":[{"name":"key","item_id":"s1","role":"secret"},{"name":"pin","item_id":"s1","role":"secret"},{"name":"doc","item_id":"s1","role":"document"}]}"#;
const SIGN_NAMED_EXAMPLE: &str = r#"{"items":[{"id":"s2","operation":{"kind":"sign","profile":"pades_t","input":"pdf","keys":[{"source":"named","name":"operator-key"}]}}],"parts":[{"name":"pdf","item_id":"s2","role":"document"}]}"#;
const EXTEND_EXAMPLE: &str = r#"{"items":[{"id":"e1","operation":{"kind":"extend","profile":"cades_lt","input":"signature","detached":"content"}}],"parts":[{"name":"signature","item_id":"e1","role":"document"},{"name":"content","item_id":"e1","role":"document"}]}"#;
const EXTRACT_EXAMPLE: &str = r#"{"items":[{"id":"x1","operation":{"kind":"extract","input":"container"}}],"parts":[{"name":"container","item_id":"x1","role":"document"}]}"#;
const JWS_EXAMPLE: &str = r#"{"items":[{"id":"j1","operation":{"kind":"jws_sign","serialization":"compact","input":"payload","keys":[{"source":"named","name":"operator-key"}]}}],"parts":[{"name":"payload","item_id":"j1","role":"document"}]}"#;
const JWT_EXAMPLE: &str = r#"{"items":[{"id":"t1","operation":{"kind":"jwt_verify","input":"token"}}],"parts":[{"name":"token","item_id":"t1","role":"document"}]}"#;
const INSPECT_EXAMPLE: &str = r#"{"items":[{"id":"i1","operation":{"kind":"inspect","target":{"type":"container","container":"p12","password":"pin"}}}],"parts":[{"name":"p12","item_id":"i1","role":"secret"},{"name":"pin","item_id":"i1","role":"secret"}]}"#;
const PLUGIN_EXAMPLE: &str = r#"{"items":[{"id":"p1","operation":{"kind":"plugin","plugin":"vendor.example","operation":"run","args":"{}","keys":[{"handle":1,"name":"operator-key"}]}}],"parts":[]}"#;
const STAMP_EXAMPLE: &str = r#"{"items":[{"id":"t2","operation":{"kind":"stamp","input":"doc"}}],"parts":[{"name":"doc","item_id":"t2","role":"document"}]}"#;
const VERIFY_STAMP_EXAMPLE: &str = r#"{"items":[{"id":"t3","operation":{"kind":"verify_stamp","token":"token","data":"doc","algorithm":"sha256","max_age_seconds":3600}}],"parts":[{"name":"token","item_id":"t3","role":"document"},{"name":"doc","item_id":"t3","role":"document"}]}"#;

const BATCH_EXAMPLE: &str = r#"{"items":[{"id":"sign-1","operation":{"kind":"sign","profile":"cades_b","input":"doc-1","attached":false,"keys":[{"source":"named","name":"operator-key"}]}},{"id":"check-1","operation":{"kind":"verify","profile":"cades_b","input":"sig-1","detached":"doc-2"}},{"id":"hash-1","operation":{"kind":"hash","algorithm":"sha256","input":"doc-3"}}],"parts":[{"name":"doc-1","item_id":"sign-1","role":"document"},{"name":"sig-1","item_id":"check-1","role":"document"},{"name":"doc-2","item_id":"check-1","role":"document"},{"name":"doc-3","item_id":"hash-1","role":"document"}]}"#;

fn parsed(example: &str) -> Value {
    // Fails the build of the document (and the contract test) if the example is
    // not accepted by the real DTO schema.
    serde_json::from_str::<OperationMetadata>(example).expect("example matches the DTO");
    serde_json::from_str(example).expect("example is JSON")
}
fn event(results: Vec<ItemResult>) -> Value {
    serde_json::to_value(ResponseEvent::Final {
        operation_id: 7,
        status: FinalStatus::Completed,
        results,
        error: None,
    })
    .expect("serializable")
}
fn failed(error: ApiError) -> Value {
    serde_json::to_value(ResponseEvent::Final {
        operation_id: 8,
        status: FinalStatus::Failed,
        results: Vec::new(),
        error: Some(error),
    })
    .expect("serializable")
}
/// Terminal record of a batch that stopped on item 2 (quota): item 1's output stands.
fn batch_event(status: BatchStatus, items: Vec<BatchItemRecord>, stop: Option<BatchStop>) -> Value {
    let completed = items
        .iter()
        .filter(|i| matches!(i.outcome, BatchItemOutcome::Completed))
        .count();
    let attempted = items
        .iter()
        .filter(|i| !matches!(i.outcome, BatchItemOutcome::NotRun))
        .count();
    serde_json::to_value(ResponseEvent::BatchFinal {
        operation_id: 9,
        status,
        attempted,
        completed,
        total: items.len(),
        stop,
        items,
        error: None,
    })
    .expect("serializable")
}
fn batch_item(
    id: &str,
    index: usize,
    outcome: BatchItemOutcome,
    applied: AppliedState,
    error: Option<ApiError>,
    result: Option<OperationResult>,
) -> BatchItemRecord {
    BatchItemRecord {
        item_id: id.into(),
        index,
        outcome,
        applied,
        verdict: result.as_ref().and_then(OperationResult::verdict),
        error,
        result,
        sources: vec![SourceIdentity {
            sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
            bytes: 3,
        }],
    }
}
fn checks() -> SignerChecks {
    SignerChecks {
        signature: "Passed",
        chain: "Passed",
        validity: "Passed",
        revocation: "Passed",
        timestamp: "Passed",
        key_usage: "Passed",
        time_basis: "VerifiedTimestamp",
        time_basis_unix: 1_793_000_000,
        claimed_signing_time_unix: Some(1_792_999_990),
        ades_level: Some("T"),
        reasons: Vec::new(),
    }
}
fn timestamp() -> TimestampFacts {
    TimestampFacts {
        verdict: "Valid",
        gen_time_unix: 1_793_000_000,
        checked_at_unix: 1_793_000_005,
        policy: "StrictOnline",
        algorithm: Some("Sha256".into()),
        imprint: "Matched".into(),
        signature: "Passed",
        eku: "Passed",
        chain: "Passed",
        validity: "Passed",
        revocation: "Passed",
        expectations: "NotApplicable",
    }
}
fn item(id: &str, applied: AppliedState, result: OperationResult) -> ItemResult {
    ItemResult {
        item_id: id.into(),
        applied,
        result,
    }
}
fn ref_(name: &str) -> Value {
    json!({"$ref": format!("#/components/schemas/{name}")})
}
fn object(required: &[&str], properties: Value) -> Value {
    json!({"type":"object","required":required,"properties":properties,"additionalProperties":false})
}
fn res(kind: &str, required: &[&str], mut properties: Value) -> Value {
    properties["kind"] = json!({"const": kind});
    let mut all = vec!["kind"];
    all.extend_from_slice(required);
    object(&all, properties)
}
fn verdict() -> Value {
    enumeration(&["Valid", "Invalid", "Indeterminate"])
}
fn check() -> Value {
    enumeration(&["Passed", "Failed", "Unavailable", "NotApplicable"])
}
fn enumeration(values: &[&str]) -> Value {
    json!({"type":"string","enum":values})
}
fn key_ref() -> Value {
    json!({"oneOf":[
        object(&["source","name"], json!({"source":{"const":"named"},"name":{"type":"string","description":"Operator-configured key name; the token must hold this exact key right."}})),
        object(&["source","container"], json!({"source":{"const":"inline"},
            "container":{"type":"string","description":"Name of a `secret` part holding a PKCS#12/JKS container. Requires global `inline_pkcs12` and the token's inline right."},
            "password":{"type":"string","description":"Name of a `secret` part holding the password."},
            "alias":{"type":"string"}}))
    ]})
}
fn schemas() -> Value {
    let doc =
        json!({"type":"string","description":"Name of a `document` part declared for this item."});
    let optional_doc = doc.clone();
    let op = |kind: &str, required: &[&str], properties: Value| {
        let mut props = properties;
        props["kind"] = json!({"const": kind});
        let mut required: Vec<&str> = required.to_vec();
        required.insert(0, "kind");
        object(&required, props)
    };
    json!({
        "ApiError": object(&["code","applied"], json!({"code": ref_("ErrorCode"), "applied": ref_("AppliedState")})),
        "ErrorCode": enumeration(&["PermissionDenied","InteractionRequired","InvalidRequest","CapacityExceeded","DeadlineExceeded","Cancelled","InputLimit","FramingLimit","MissingTemporaryStore","MemoryLimit","TempLimit","MetadataLimit","OutputLimit","AuditUnavailable","MissingConfiguration","KeyNotFound","ValidationFailed","OperationFailed","Internal"]),
        "AppliedState": {"enum":["NotApplied","Applied","Unknown"],"description":"Whether a private key was used. `Unknown` after a post-use failure; no rollback or exactly-once is promised."},
        "OperationMetadata": object(&["items","parts"], json!({
            "items":{"type":"array","minItems":1,"maxItems":1024,"items":ref_("Item")},
            "parts":{"type":"array","maxItems":2048,"items":ref_("Part")}})),
        "Item": object(&["id","operation"], json!({"id":{"type":"string","pattern":"^[A-Za-z0-9_-]{1,128}$"},"operation":ref_("Operation")})),
        "Part": object(&["name","item_id","role"], json!({
            "name":{"type":"string","pattern":"^[A-Za-z0-9_-]{1,128}$"},
            "item_id":{"type":"string"},
            "role":{"enum":["document","secret"],"description":"Role is decided by this metadata, never by filename or Content-Type. `secret` parts are bounded zeroizing memory and are never written to the document spool. All `secret` parts must be declared and sent before every `document` part."}})),
        "KeyRef": key_ref(),
        "Operation": {"oneOf":[
            ref_("HashOperation"), ref_("VerifyOperation"), ref_("ExtractOperation"), ref_("SignOperation"),
            ref_("ExtendOperation"), ref_("InspectOperation"), ref_("StampOperation"), ref_("VerifyStampOperation"),
            ref_("JwsSignOperation"), ref_("JwsAddOperation"), ref_("JwsVerifyOperation"),
            ref_("JwtEncodeOperation"), ref_("JwtDecodeOperation"), ref_("JwtVerifyOperation"), ref_("PluginOperation")],
            "discriminator":{"propertyName":"kind"}},
        "HashOperation": op("hash", &["algorithm","input"], json!({"algorithm":enumeration(&["sha1","sha256","sha512","gost34311","streebog256","streebog512"]),"input":doc})),
        "VerifyOperation": op("verify", &["profile","input"], json!({"profile":enumeration(&["cms","cades_b","cades_t","cades_lt","cades_lta","pdf","pades_b","pades_t","pades_lt","pades_lta","xml","xml_kalkan","xades_b","xades_t","xades_lt","xades_lta","wsse"]),"input":doc,"detached":optional_doc,"soap":enumeration(&["soap11","soap12"])})),
        "ExtractOperation": op("extract", &["input"], json!({"input":doc})),
        "SignOperation": op("sign", &["profile","input","keys"], json!({"profile":enumeration(&["cms","cades_b","cades_t","cades_lt","cades_lta","pdf","pades_b","pades_t","pades_lt","pades_lta","xml","xades_b","xades_t","wsse","xml_legacy","xades_legacy_b","xades_legacy_t"]),"input":doc,"detached":doc,"soap":enumeration(&["soap11","soap12"]),"body_id":{"type":"string"},"element":{"type":"string","description":"xml_legacy/xades_legacy_b: XPath of the element to sign"},"xpath_parent":{"type":"string"},"signature_method":{"type":"string"},"digest_method":{"type":"string"},"evidence":{"type":"array","items":object(&["kind","input"],json!({"kind":enumeration(&["certificate","ocsp","crl"]),"input":{"type":"string"}}))},"target":{"type":"string","description":"XML/XAdES unique element ID to sign"},"parent":{"type":"string","description":"XML/XAdES unique element ID receiving the signature"},"signature_id":{"type":"string"},"mode":enumeration(&["create","add"]),"attached":{"type":"boolean"},"keys":{"type":"array","minItems":1,"maxItems":8,"items":ref_("KeyRef")}})),
        "ExtendOperation": op("extend", &["profile","input"], json!({"profile":enumeration(&["cades_t","cades_lt","cades_lta","pades_t","pades_lt","pades_lta","xades_lt","xades_lta"]),"input":doc,"detached":doc,"evidence":{"type":"array","items":object(&["kind","input"],json!({"kind":enumeration(&["certificate","ocsp","crl"]),"input":{"type":"string"}}))}})),
        "InspectOperation": op("inspect", &["target"], json!({"target":{"oneOf":[
            object(&["type","input"], json!({"type":{"const":"certificate"},"input":doc})),
            object(&["type","input"], json!({"type":{"const":"cms"},"input":doc})),
            object(&["type","container"], json!({"type":{"const":"container"},"container":{"type":"string"},"password":{"type":"string"}})),
            object(&["type","name"], json!({"type":{"const":"named"},"name":{"type":"string"}}))]}})),
        "StampOperation": op("stamp", &["input"], json!({"input":doc})),
        "VerifyStampOperation": op("verify_stamp", &["token"], json!({"token":doc,"data":doc,"algorithm":enumeration(&["sha1","sha256","sha512","gost34311","streebog256","streebog512"]),"max_age_seconds":{"type":"integer","minimum":0}})),
        "JwsSignOperation": op("jws_sign", &["serialization","input","keys"], json!({"serialization":enumeration(&["compact","flattened","general"]),"detached":{"type":"boolean"},"input":doc,"keys":{"type":"array","items":ref_("KeyRef")}})),
        "JwsAddOperation": op("jws_add", &["serialization","input","keys"], json!({"serialization":enumeration(&["compact","flattened","general"]),"input":doc,"detached":doc,"certificate":doc,"keys":{"type":"array","items":ref_("KeyRef")}})),
        "JwsVerifyOperation": op("jws_verify", &["serialization","input"], json!({"serialization":enumeration(&["compact","flattened","general"]),"input":doc,"detached":doc,"certificate":doc})),
        "JwtEncodeOperation": op("jwt_encode", &["input","key"], json!({"input":doc,"key":ref_("KeyRef")})),
        "JwtDecodeOperation": op("jwt_decode", &["input"], json!({"input":doc})),
        "PluginOperation": op("plugin", &["plugin","operation","args"], json!({"plugin":{"type":"string"},"operation":{"type":"string"},"args":{"type":"string","description":"JSON text for the plugin"},"keys":{"type":"array","items":object(&["handle","name"], json!({"handle":{"type":"integer"},"name":{"type":"string","description":"operator-named key granted to this token and plugin operation"}}))}})),
        "PluginResult": res("plugin", &["response","applied"], json!({"response":{"type":"string"},"applied":ref_("AppliedState")})),
        "JwtVerifyOperation": op("jwt_verify", &["input"], json!({"input":doc,"certificate":doc})),
        "FinalEvent": object(&["type","operation_id","status","results"], json!({
            "type":{"const":"final"},
            "operation_id":{"type":"integer"},
            "status":{"enum":["completed","failed"],"description":"Mandatory terminal record. `completed` means every item finished (an Invalid verification is completed). `failed` carries `error` with the honest Applied state; its artifacts are withheld."},
            "results":{"type":"array","items":ref_("ItemResult")},
            "error":ref_("ApiError")})),
        "ItemResult": object(&["item_id","applied","result"], json!({"item_id":{"type":"string"},"applied":ref_("AppliedState"),"result":ref_("OperationResult")})),
        "OperationResult": {"oneOf":[ref_("HashResult"),ref_("VerificationResult"),ref_("ExtractionResult"),ref_("SigningResult"),ref_("ExtensionResult"),ref_("InspectionResult"),ref_("StampingResult"),ref_("StampVerificationResult"),ref_("JwsResult"),ref_("JwsVerificationResult"),ref_("JwtDecodedResult"),ref_("JwtVerificationResult"),ref_("PluginResult")],"discriminator":{"propertyName":"kind"},"description":"Typed by `kind`. Artifact-producing results carry `artifact`, the Content-ID of a binary part; a failed final omits it (artifacts are withheld)."},
        "HashResult": res("hash", &["algorithm","digest","bytes_in"], json!({"algorithm":{"type":"string"},"digest":{"type":"string"},"bytes_in":{"type":"integer"}})),
        "VerificationResult": res("verification", &["profile","verdict","policy","checked_at_unix","signers"], json!({"profile":{"type":"string"},"verdict":verdict(),"policy":{"type":"string"},"checked_at_unix":{"type":"integer"},"signers":{"type":"array","items":ref_("SignerChecks")}})),
        "ExtractionResult": res("extraction", &["bytes_written"], json!({"artifact":{"type":"string"},"bytes_written":{"type":"integer"}})),
        "SigningResult": res("signing", &["profile","bytes_in","bytes_out","signers"], json!({"profile":{"type":"string"},"artifact":{"type":"string"},"bytes_in":{"type":"integer"},"bytes_out":{"type":"integer"},"signers":{"type":"array","items":ref_("AppliedState")}})),
        "ExtensionResult": res("extension", &["profile","bytes_in","bytes_out","verdicts"], json!({"profile":{"type":"string"},"artifact":{"type":"string"},"bytes_in":{"type":"integer"},"bytes_out":{"type":"integer"},"verdicts":{"type":"array","items":verdict()}})),
        "InspectionResult": res("inspection", &["target","bytes_in","entries"], json!({"target":{"type":"string"},"bytes_in":{"type":"integer"},"integrity":{"type":"string"},"entries":{"type":"array","items":ref_("InspectedEntry")},"cms":ref_("InspectedCms")})),
        "StampingResult": res("stamping", &["bytes_in","bytes_out","timestamp"], json!({"artifact":{"type":"string"},"bytes_in":{"type":"integer"},"bytes_out":{"type":"integer"},"timestamp":ref_("TimestampFacts")})),
        "StampVerificationResult": res("stamp_verification", &["bytes_in","timestamp"], json!({"bytes_in":{"type":"integer"},"timestamp":ref_("TimestampFacts")})),
        "JwsResult": res("jws", &["serialization","bytes_in","bytes_out","signers"], json!({"serialization":{"type":"string"},"artifact":{"type":"string"},"bytes_in":{"type":"integer"},"bytes_out":{"type":"integer"},"signers":{"type":"array","items":ref_("AppliedState")}})),
        "JwsVerificationResult": res("jws_verification", &["verdict","policy","checked_at_unix","signers"], json!({"verdict":verdict(),"policy":{"type":"string"},"checked_at_unix":{"type":"integer"},"signers":{"type":"array","items":ref_("JwsSignerFacts")}})),
        "JwtDecodedResult": res("jwt_decoded", &["verified","audience","claims"], json!({"verified":{"const":false},"issuer":{"type":["string","null"]},"audience":{"type":"array","items":{"type":"string"}},"expiration_unix":{"type":["integer","null"]},"claims":{"type":"string"}})),
        "JwtVerificationResult": res("jwt_verification", &["verdict","signature_verdict","claims_verdict","claim_failures","checked_at_unix","signers","claims"], json!({"verdict":verdict(),"signature_verdict":verdict(),"claims_verdict":verdict(),"claim_failures":{"type":"array","items":{"type":"string"}},"checked_at_unix":{"type":"integer"},"signers":{"type":"array","items":ref_("JwsSignerFacts")},"claims":{"type":"string"}})),
        "SignerChecks": object(&["signature","chain","validity","revocation","timestamp","key_usage","time_basis","time_basis_unix","reasons"], json!({"signature":check(),"chain":check(),"validity":check(),"revocation":check(),"timestamp":check(),"key_usage":check(),"time_basis":{"type":"string"},"time_basis_unix":{"type":"integer"},"claimed_signing_time_unix":{"type":["integer","null"]},"ades_level":{"type":["string","null"]},"reasons":{"type":"array","items":{"type":"string"}}})),
        "TimestampFacts": object(&["verdict","gen_time_unix","checked_at_unix","policy","imprint","signature","eku","chain","validity","revocation","expectations"], json!({"verdict":verdict(),"gen_time_unix":{"type":"integer"},"checked_at_unix":{"type":"integer"},"policy":{"type":"string"},"algorithm":{"type":["string","null"]},"imprint":{"enum":["NotProvided","Matched","Mismatched"]},"signature":check(),"eku":check(),"chain":check(),"validity":check(),"revocation":check(),"expectations":check()})),
        "JwsSignerFacts": object(&["algorithm","crypto","verdict","trust"], json!({"algorithm":{"type":"string"},"crypto":check(),"verdict":verdict(),"trust":ref_("SignerChecks")})),
        "InspectedEntry": object(&["alias","subject_cn","serial_hex","sha256","signature_algorithm_oid","public_key_algorithm_oid","not_before_unix","not_after_unix"], json!({"alias":{"type":["string","null"]},"subject_cn":{"type":["string","null"]},"serial_hex":{"type":["string","null"]},"sha256":{"type":["string","null"]},"signature_algorithm_oid":{"type":["string","null"]},"public_key_algorithm_oid":{"type":["string","null"]},"not_before_unix":{"type":["integer","null"]},"not_after_unix":{"type":["integer","null"]}})),
        "InspectedCms": object(&["detached","content_len","signer_count"], json!({"detached":{"type":"boolean"},"content_len":{"type":"integer"},"signer_count":{"type":"integer"}})),
        "ProgressEvent": object(&["type","operation_id","bytes_in","bytes_out"], json!({"type":{"const":"progress"},"operation_id":{"type":"integer"},"bytes_in":{"type":"integer"},"bytes_out":{"type":"integer"},"items":object(&["total","finished","current"], json!({"total":{"type":"integer"},"finished":{"type":"integer"},"current":{"description":"Item being processed (batch only); null between items","oneOf":[{"type":"null"},object(&["index","item_id"], json!({"index":{"type":"integer"},"item_id":{"type":"string"}}))]}}))})),
        "BatchFinalEvent": object(&["type","operation_id","status","attempted","completed","total","items"], json!({
            "type":{"const":"batch_final"},
            "operation_id":{"type":"integer"},
            "status":{"enum":["completed","partial","failed"],"description":"Mandatory terminal record of /v1/batch. `completed`: every item completed. `partial`: some item failed or did not run; completed items and their artifacts stand (nothing is rolled back). `failed`: nothing could run (`error`)."},
            "attempted":{"type":"integer"},"completed":{"type":"integer"},"total":{"type":"integer"},
            "stop":ref_("BatchStop"),
            "items":{"type":"array","items":ref_("BatchItemRecord"),"description":"One record per manifest item, in manifest order."},
            "error":ref_("ApiError")})),
        "BatchStop": object(&["kind","code","applied"], json!({"kind":{"enum":["control","item"],"description":"`control`: cancel/deadline/lost resource before the next item; `item`: a terminal item failure (quota, audit, deadline or cancel during the item). Later items are `not_run`; nothing is retried."},"code":ref_("ErrorCode"),"item_index":{"type":"integer"},"applied":ref_("AppliedState")})),
        "BatchItemRecord": object(&["item_id","index","outcome","applied","sources"], json!({
            "item_id":{"type":"string"},"index":{"type":"integer"},
            "outcome":{"enum":["completed","failed","not_run"]},
            "applied":ref_("AppliedState"),
            "verdict":verdict(),
            "error":ref_("ApiError"),
            "result":ref_("OperationResult"),
            "sources":{"type":"array","items":ref_("SourceIdentity"),"description":"SHA-256 and length of the exact source bytes captured for this item (the bytes actually processed)."}})),
        "SourceIdentity": object(&["sha256","bytes"], json!({"sha256":{"type":"string"},"bytes":{"type":"integer"}}))
    })
}
fn request_body() -> Value {
    json!({"required":true,"content":{
        "multipart/form-data":{
            "schema":{"type":"object","description":"First part `metadata` (OperationMetadata JSON). Then the declared `secret` parts, then the declared `document` parts, in `parts` order. Unknown, duplicate, late or unused parts are rejected before private use. Filenames are untrusted and never become filesystem names.","properties":{"metadata":ref_("OperationMetadata")}},
            "examples":{
                "hash":{"summary":"Hash a binary document","value":parsed(HASH_EXAMPLE)},
                "sign_inline":{"summary":"CAdES-B with an inline container (secret roles sent first)","value":parsed(SIGN_EXAMPLE)},
                "sign_named":{"summary":"PAdES-T with an operator-named key","value":parsed(SIGN_NAMED_EXAMPLE)},
                "verify":{"summary":"Verify a detached CAdES-T","value":parsed(VERIFY_EXAMPLE)},
                "extend":{"summary":"Keyless extension to CAdES-LT","value":parsed(EXTEND_EXAMPLE)},
                "extract":{"summary":"Extract attached content","value":parsed(EXTRACT_EXAMPLE)},
                "jws":{"summary":"Compact JWS","value":parsed(JWS_EXAMPLE)},
                "jwt_verify":{"summary":"JWT with host-owned issuer/audience policy","value":parsed(JWT_EXAMPLE)},
                "inspect":{"summary":"Container metadata for host-granted aliases","value":parsed(INSPECT_EXAMPLE)},
                "plugin":{"summary":"Operator-granted plugin call (imports/keys come from operator grants)","value":parsed(PLUGIN_EXAMPLE)},
                "stamp":{"summary":"Timestamp from the operator-configured TSA","value":parsed(STAMP_EXAMPLE)},
                "verify_stamp":{"summary":"Verify a token against its data","value":parsed(VERIFY_STAMP_EXAMPLE)}}},
        "application/json":{
            "schema":{"type":"object","required":["metadata","documents"],"properties":{"metadata":ref_("OperationMetadata"),"documents":{"type":"object","additionalProperties":{"type":"string"}}},"description":"Small public text documents only (<= 65536 bytes). `secret` parts are not accepted in JSON."},
            "example":{"metadata":parsed(HASH_EXAMPLE),"documents":{"doc":"abc"}}}}})
}
fn batch_responses() -> Value {
    let signed = || OperationResult::Signing {
        profile: SignKind::CadesB,
        artifact: Some("artifact-0".into()),
        bytes_in: 3,
        bytes_out: 1812,
        signers: vec![AppliedState::Applied],
    };
    let invalid = OperationResult::Verification {
        profile: VerifyProfile::CadesB,
        verdict: "Invalid",
        policy: "StrictOnline",
        checked_at_unix: 1_767_000_000,
        signers: vec![checks()],
    };
    let hashed = OperationResult::Hash {
        algorithm: HashAlgorithm::Sha256,
        digest: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
        bytes_in: 3,
    };
    let mixed = batch_event(
        BatchStatus::Completed,
        vec![
            batch_item(
                "sign-1",
                0,
                BatchItemOutcome::Completed,
                AppliedState::Applied,
                None,
                Some(signed()),
            ),
            batch_item(
                "check-1",
                1,
                BatchItemOutcome::Completed,
                AppliedState::NotApplied,
                None,
                Some(invalid),
            ),
            batch_item(
                "hash-1",
                2,
                BatchItemOutcome::Completed,
                AppliedState::NotApplied,
                None,
                Some(hashed),
            ),
        ],
        None,
    );
    let stopped = batch_event(
        BatchStatus::Partial,
        vec![
            batch_item(
                "sign-1",
                0,
                BatchItemOutcome::Completed,
                AppliedState::Applied,
                None,
                Some(signed()),
            ),
            batch_item(
                "sign-2",
                1,
                BatchItemOutcome::Failed,
                AppliedState::NotApplied,
                Some(ApiError {
                    code: ErrorCode::TempLimit,
                    applied: AppliedState::NotApplied,
                }),
                None,
            ),
            batch_item(
                "hash-1",
                2,
                BatchItemOutcome::NotRun,
                AppliedState::NotApplied,
                None,
                None,
            ),
        ],
        Some(BatchStop {
            kind: BatchStopKind::Item,
            code: ErrorCode::TempLimit,
            item_index: Some(1),
            applied: AppliedState::NotApplied,
        }),
    );
    let error = |description: &str, example: ErrorCode| json!({"description":description,"content":{"application/json":{"schema":ref_("ApiError"),"example":ApiError{code:example,applied:AppliedState::NotApplied}}}});
    json!({
        "200":{"description":"Always `multipart/mixed`: coalesced `progress` parts (with per-item position), one `artifact` part per FINISHED output (opaque Content-ID named by that item's result), and a mandatory `batch_final` part last (multipart name `final`). A stream without a terminal record is an unknown outcome, never a success. If the original deadline expires or the client disconnects mid-batch the response is aborted without a terminal record (no byte may leave after the deadline); the durable audit journal holds the per-item facts.",
            "content":{"multipart/mixed":{"schema":{"type":"object","description":"Wire order: progress*, artifact*, final (last).","required":["final"],"properties":{"progress":{"type":"array","items":ref_("ProgressEvent")},"artifact":{"type":"array","items":{"type":"string","format":"binary"}},"final":ref_("BatchFinalEvent")}},"examples":{"mixed":{"summary":"Sign, verify (Invalid is a completed item) and hash","value":mixed},"quota_stop":{"summary":"Item 2 hit a terminal quota: item 1's artifact stands, item 3 not run","value":stopped}}}}},
        "400":error("Malformed or confused metadata, plugin item, unknown/duplicate/late/unused part, secret in JSON",ErrorCode::InvalidRequest),
        "403":error("Token lacks the batch right, or any item's operation/key/inline right is not granted (the whole batch is refused before any document or secret is read), or the captured plan did not match the authorized composition",ErrorCode::PermissionDenied),
        "408":error("The request was cancelled before the batch started",ErrorCode::Cancelled),
        "413":error("Document, framing, memory, temp, metadata or output limit before the batch started",ErrorCode::InputLimit),
        "422":error("Validation failure before the batch started",ErrorCode::ValidationFailed),
        "503":error("Capacity, audit or required host configuration unavailable; nothing was applied",ErrorCode::CapacityExceeded),
        "504":error("The original operation deadline expired before the batch started",ErrorCode::DeadlineExceeded)})
}
fn responses() -> Value {
    let hash = event(vec![item(
        "h1",
        AppliedState::NotApplied,
        OperationResult::Hash {
            algorithm: HashAlgorithm::Sha256,
            digest: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
            bytes_in: 3,
        },
    )]);
    let verification = event(vec![item(
        "v1",
        AppliedState::NotApplied,
        OperationResult::Verification {
            profile: VerifyProfile::CadesT,
            verdict: "Invalid",
            policy: "StrictOnline",
            checked_at_unix: 1_793_000_005,
            signers: vec![SignerChecks {
                signature: "Failed",
                ..checks()
            }],
        },
    )]);
    let signing = event(vec![item(
        "s1",
        AppliedState::Applied,
        OperationResult::Signing {
            profile: SignKind::CadesB,
            artifact: Some("artifact-0".into()),
            bytes_in: 1024,
            bytes_out: 6144,
            signers: vec![AppliedState::Applied],
        },
    )]);
    let jws_verify = event(vec![item(
        "j2",
        AppliedState::NotApplied,
        OperationResult::JwsVerification {
            verdict: "Valid",
            policy: "StrictOnline",
            checked_at_unix: 1_793_000_005,
            signers: vec![JwsSignerFacts {
                algorithm: "RS256",
                crypto: "Passed",
                verdict: "Valid",
                trust: checks(),
            }],
        },
    )]);
    let stamp = event(vec![item(
        "t2",
        AppliedState::NotApplied,
        OperationResult::Stamping {
            artifact: Some("artifact-0".into()),
            bytes_in: 1024,
            bytes_out: 3500,
            timestamp: timestamp(),
        },
    )]);
    let inspect = event(vec![item(
        "i1",
        AppliedState::NotApplied,
        OperationResult::Inspection {
            target: "container",
            bytes_in: 4096,
            integrity: Some("PasswordMacVerified".into()),
            entries: vec![InspectedEntry {
                alias: Some("alias".into()),
                subject_cn: Some("Example".into()),
                serial_hex: Some("01".into()),
                sha256: None,
                signature_algorithm_oid: None,
                public_key_algorithm_oid: None,
                not_before_unix: None,
                not_after_unix: None,
            }],
            cms: None::<InspectedCms>,
        },
    )]);
    let failure = failed(ApiError {
        code: ErrorCode::AuditUnavailable,
        applied: AppliedState::NotApplied,
    });
    let after_use = failed(ApiError {
        code: ErrorCode::OperationFailed,
        applied: AppliedState::Unknown,
    });
    let error = |description: &str, example: ErrorCode| json!({"description":description,"content":{"application/json":{"schema":ref_("ApiError"),"example":ApiError{code:example,applied:AppliedState::NotApplied}}}});
    json!({
        "200":{"description":"Operations without a binary artifact return one JSON `final` record. Operations that produce a binary artifact (extract, sign, extend, stamp, jws/jwt creation) return `multipart/mixed`: coalesced `progress` JSON parts, one `artifact` part per output (opaque `Content-ID` named by the result's `artifact`, exact `Content-Length`), and a mandatory `final` part last. A stream without a terminal `final` of status `completed` is not a success. Before headers, failures are typed JSON errors with a status code; after headers the status cannot change, so failures are reported in `final` (status `failed`, honest Applied state, artifacts withheld) or by transport abort.",
            "content":{
                "application/json":{"schema":ref_("FinalEvent"),"examples":{"hash":{"value":hash},"verification_invalid_is_200":{"summary":"A bad signature is a completed Invalid report, never HTTP 500","value":verification},"jws_verification":{"value":jws_verify},"inspection":{"value":inspect}}},
                "multipart/mixed":{"schema":{"type":"object","description":"Wire order: progress*, artifact*, final (last). `progress` and `final` parts are application/json; `artifact` parts are application/octet-stream with a Content-ID.","required":["final"],"properties":{"progress":{"type":"array","items":ref_("ProgressEvent")},"artifact":{"type":"array","items":{"type":"string","format":"binary"}},"final":ref_("FinalEvent")}},"examples":{"signed":{"summary":"Terminal record of a signing stream","value":signing},"stamp":{"value":stamp},"failed_before_use":{"value":failure},"failed_after_use":{"summary":"Key use is unknown after a post-use failure","value":after_use}}}}},
        "400":error("Malformed or confused metadata, unknown/duplicate/late/unused part, secret in JSON",ErrorCode::InvalidRequest),
        "403":error("Token, operation, key or inline right not granted",ErrorCode::PermissionDenied),
        "404":error("Unknown path or operation route (no NCANode aliases, no plugin/encryption routes)",ErrorCode::InvalidRequest),
        "408":error("The request was cancelled before completion",ErrorCode::Cancelled),
        "413":error("Document, framing, memory, temp, metadata or output limit",ErrorCode::InputLimit),
        "422":error("Validation or operation failure before any response header",ErrorCode::ValidationFailed),
        "500":error("Internal failure",ErrorCode::Internal),
        "503":error("Capacity (no slot freed within the server's admission wait), audit or required host configuration unavailable; nothing was applied",ErrorCode::CapacityExceeded),
        "504":error("The original operation deadline expired, or the upload stalled (no byte within the idle timeout) or fell below the server's minimum upload rate; before key use, nothing was applied",ErrorCode::DeadlineExceeded)})
}
/// Resource profile text shown in the `sign`/`extend` operation descriptions.
const LT_PROFILE: &str = "cades_lt/lta, pades_lt/lta (sign and extend) and xades_lt/lta (extend) require `evidence` with at least one `ocsp` or `crl` part (400 before any key/secret is read otherwise). xades_lt/lta are produced by signing xades_t and then a keyless extend (the SDK XML sign request carries no status material). pades_lt/lta need the PDF update plan's memory and metadata (oncl_pdf::budget::plan_memory/plan_metadata from the document's existing signatures, the evidence sizes and the trust set, plus named host reservations; about 380 MiB at default limits with small evidence) available in the operation scope: 413 MemoryLimit/MetadataLimit before any audit BEGIN otherwise. Empirically sufficient for the tested fixtures and evidence shapes, not a proof for every PDF. xades_t/xades_legacy_t need a host TSA policy OID (503 MissingConfiguration).";
/// The complete OpenAPI document served at `GET /v1/openapi.json`.
pub fn document() -> Value {
    json!({
        "openapi":"3.1.0",
        "info":{"title":"OpenNCALayer HTTP API","version":"1","description":"Own `/v1` contract (not NCANode wire-compatible). Disabled by default; loopback with per-token rights. Encryption/decryption operations are not part of this contract."},
        "security":[{"bearer":[]}],
        "paths":{
            "/health":{"get":{"summary":"Service and audit health","responses":{"200":{"description":"healthy"},"503":{"description":"audit unavailable"}}}},
            "/v1/openapi.json":{"get":{"summary":"This document","responses":{"200":{"description":"OpenAPI document","content":{"application/json":{}}}}}},
            "/v1/hash":{"post":{"summary":"Raw streaming SHA-256","requestBody":{"required":true,"content":{"application/octet-stream":{"schema":{"type":"string","format":"binary"}}}},"responses":{"200":{"description":"digest","content":{"application/json":{"schema":object(&["operation_id","algorithm","digest","bytes_in"],json!({"operation_id":{"type":"integer"},"algorithm":{"const":"sha256"},"digest":{"type":"string"},"bytes_in":{"type":"integer"}}))}}}}}},
            "/v1/operations":{"post":{"summary":"Typed operations","x-lt-profile":LT_PROFILE,"description":"One request carries 1..1024 items executed sequentially under one original deadline and resource budget. Every private use is bound to the authenticated actor and exact key and is durably audited before the key is applied.","requestBody":request_body(),"responses":responses()}},
            "/v1/batch":{"post":{"summary":"Closed batch with explicit host approval","description":"1..1024 ordered items (same item DTOs and part roles as `/v1/operations`, except `plugin`, which is refused) captured as immutable sources, approved by the host for exactly that composition, then run sequentially under one original deadline and budget. Needs the token's `batch` right AND every item's own operation/key/inline right; all are decided before any document or secret byte is read. A failing item never erases completed items; after a terminal stop (quota, audit, deadline, cancel) later items are `not_run`. No retries, idempotency or rollback. Every private use is audited with its batch item ordinal.","requestBody":{"required":true,"content":{"multipart/form-data":{"schema":{"type":"object","description":"First part `metadata` (the OperationMetadata manifest), then secret parts, then document parts in `parts` order. The metadata carries no approval, grant or authority flag: unknown fields are rejected.","properties":{"metadata":ref_("OperationMetadata")}},"examples":{"mixed":{"summary":"Sign, verify and hash in one batch","value":parsed(BATCH_EXAMPLE)}}},"application/json":{"schema":{"type":"object","required":["metadata","documents"],"properties":{"metadata":ref_("OperationMetadata"),"documents":{"type":"object","additionalProperties":{"type":"string"}}},"description":"Small public text documents only (<= 65536 bytes). `secret` parts are not accepted in JSON."},"example":{"metadata":parsed(BATCH_EXAMPLE),"documents":{"doc-1":"abc","sig-1":"...","doc-2":"abc","doc-3":"abc"}}}}},"responses":batch_responses()}}},
        "components":{"securitySchemes":{"bearer":{"type":"http","scheme":"bearer"}},"schemas":schemas()}
    })
}
