//! `kz.qiwi.osgi.SecurityUtils`: `signXml` is NOT declared. The module asks `keys_sign_xml_ex`
//! for `transforms = [Enveloped, C14N-with-comments]`; no profile can say `transforms`
//! (`oncl_plugin::operations::XmlExProfile`, `ticket.rs::xml_ex_profile`), so Core refuses
//! the call whatever the declaration. The probe appends the closest declaration and shows the
//! refusal before the key.
use crate::ports::*;
use crate::wave3_kit::*;
use oncl_core::plugins::PluginParam;

const PROBE: &str = r#"
[[operations]]
name = "probe"
module = "kz.qiwi.osgi.SecurityUtils"
manual = true
request = '{"module":"kz.qiwi.osgi.SecurityUtils","method":"signXml","args":["1","{xml}"]}'
label = { ru = "а", kk = "ә", en = "a" }

[[operations.params]]
name = "xml"
kind = "text"
max_chars = 1000

[operations.uses]
imports = ["keys_select", "keys_release", "random", "cert_info", "now", "keys_sign_xml_ex", "xml_verify"]
network = "pki"

[[operations.uses.key]]
kind = "xml_ex"
content = "param:xml"

[operations.uses.key.profile]
placement = "first_child_of_document"
signature_method = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
digest_method = "http://www.w3.org/2001/04/xmlenc#sha256"
c14n = "inclusive"
output = { serialize = { declaration = true, standalone_no = true, trim = false } }
"#;

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn the_transforms_the_module_asks_for_cannot_be_declared() {
    let run = probe("qiwi", "probe", PROBE, &[("xml", PluginParam::Text("<r/>"))]);
    assert_refused_before_the_key(&run);
    assert_eq!(run.applications, 0);
}
