use oncl_pki::{
    io::{Source, TemporaryStore},
    resource::{OperationControl, ProcessingError, Progress, ResourceLimits, SharedBudget},
};
use oncl_xml::{C14n, C14nProfile, XmlDocument, XmlLimits};
use std::{io::Cursor, sync::Arc};
struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
#[test]
fn namespace_and_xml_lang_vectors() {
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let xml = b"<r xmlns:p='urn:p' xml:lang='outer'><a xml:lang='inner'><p:x Id='x' z='&quot;' a='a&#10;b'/></a></r>";
    let mut doc = XmlDocument::index(
        Source::sequential(&mut Cursor::new(xml), None),
        &XmlLimits::default(),
        &store,
        &mut scope,
    )
    .unwrap();
    let node = doc.lookup_id("x").unwrap().unwrap();
    for (profile, inherited) in [
        (C14nProfile::Standard, "inner"),
        (C14nProfile::KalkanLegacy, "outer"),
    ] {
        let mut output = Vec::new();
        doc.canonicalize(
            Some(&node),
            C14n::Inclusive,
            profile,
            &mut output,
            &mut scope,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            format!(
                "<p:x xmlns:p=\"urn:p\" Id=\"x\" a=\"a&#xA;b\" z=\"&quot;\" xml:lang=\"{inherited}\"></p:x>"
            )
        );
    }
}

fn canonical(xml: &[u8], method: C14n) -> Vec<u8> {
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let mut doc = XmlDocument::index(
        Source::sequential(&mut Cursor::new(xml), None),
        &XmlLimits::default(),
        &store,
        &mut scope,
    )
    .unwrap();
    let mut output = Vec::new();
    doc.canonicalize(None, method, C14nProfile::Standard, &mut output, &mut scope)
        .unwrap();
    output
}

#[test]
fn w3c_processing_instructions_and_outer_comments() {
    // Canonical XML 1.0 §3.1, without its forbidden DTD.
    let xml = b"<?xml version=\"1.0\"?>\n\n<?xml-stylesheet   href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n\n<doc>Hello, world!<!-- Comment 1 --></doc>\n\n<?pi-without-data     ?>\n\n<!-- Comment 2 -->\n\n<!-- Comment 3 -->\n";
    let expected = b"<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n<doc>Hello, world!<!-- Comment 1 --></doc>\n<?pi-without-data?>\n<!-- Comment 2 -->\n<!-- Comment 3 -->";
    assert_eq!(canonical(xml, C14n::InclusiveWithComments), expected);
}

#[test]
fn w3c_character_modifications_and_references() {
    // Canonical XML 1.0 §3.4; DTD-dependent attributes are omitted.
    let xml = "<doc>\n   <text>First line&#x0d;&#10;Second line</text>\n   <value>&#x32;</value>\n   <compute><![CDATA[value>\"0\" && value<\"10\" ?\"valid\":\"error\"]]></compute>\n   <compute expr='value>\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"'>valid</compute>\n   <norm attr=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>\n</doc>";
    let expected = "<doc>\n   <text>First line&#xD;\nSecond line</text>\n   <value>2</value>\n   <compute>value&gt;\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"</compute>\n   <compute expr=\"value>&quot;0&quot; &amp;&amp; value&lt;&quot;10&quot; ?&quot;valid&quot;:&quot;error&quot;\">valid</compute>\n   <norm attr=\" '    &#xD;&#xA;&#x9;   ' \"></norm>\n</doc>";
    assert_eq!(
        canonical(xml.as_bytes(), C14n::Inclusive),
        expected.as_bytes()
    );
}

#[test]
fn namespace_shadow_empty_default_comments_and_utf8_chunk_edges() {
    let xml=b"<r xmlns='urn:r' xmlns:p='urn:outer'><p:x xmlns:p='urn:inner' b='2' a='1'/><u xmlns=''><p:x/><!--c--></u></r>";
    let inclusive=b"<r xmlns=\"urn:r\" xmlns:p=\"urn:outer\"><p:x xmlns:p=\"urn:inner\" a=\"1\" b=\"2\"></p:x><u xmlns=\"\"><p:x></p:x><!--c--></u></r>";
    assert_eq!(canonical(xml, C14n::InclusiveWithComments), inclusive);
    let exclusive=b"<r xmlns=\"urn:r\"><p:x xmlns:p=\"urn:inner\" a=\"1\" b=\"2\"></p:x><u xmlns=\"\"><p:x xmlns:p=\"urn:outer\"></p:x></u></r>";
    assert_eq!(canonical(xml, C14n::Exclusive), exclusive);
    let spaces = " ".repeat(262143);
    let xml = format!("<r a='{spaces}қ&#13;&#10;&amp;'>т&#xD;\r\nж</r>");
    let expected = format!("<r a=\"{spaces}қ&#xD;&#xA;&amp;\">т&#xD;\nж</r>");
    assert_eq!(
        canonical(xml.as_bytes(), C14n::Inclusive),
        expected.as_bytes()
    );
}

#[test]
fn unchanged_deep_namespace_context_is_not_retained_or_charged_per_level() {
    let xml = format!(
        "<r xmlns:p=\"urn:{}\">{}content{}</r>",
        "x".repeat(20000),
        "<n>".repeat(199),
        "</n>".repeat(199)
    );
    assert_eq!(canonical(xml.as_bytes(), C14n::Inclusive), xml.as_bytes());
}

#[test]
fn standard_profile_rejects_relative_namespace_without_changing_legacy_bytes() {
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let xml = b"<r xmlns:p='relative'><p:x/></r>";
    let mut doc = XmlDocument::index(
        Source::sequential(&mut Cursor::new(xml), None),
        &XmlLimits::default(),
        &store,
        &mut scope,
    )
    .unwrap();
    assert!(
        doc.canonicalize(
            None,
            C14n::Inclusive,
            C14nProfile::Standard,
            &mut Vec::new(),
            &mut scope
        )
        .is_err()
    );
    let mut legacy = Vec::new();
    doc.canonicalize(
        None,
        C14n::Inclusive,
        C14nProfile::KalkanLegacy,
        &mut legacy,
        &mut scope,
    )
    .unwrap();
    assert_eq!(legacy, b"<r xmlns:p=\"relative\"><p:x></p:x></r>");
}
