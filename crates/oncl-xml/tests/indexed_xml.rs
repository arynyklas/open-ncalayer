use oncl_pki::io::{Source, TemporaryStore};
use oncl_pki::resource::{
    OperationControl, ProcessingError, Progress, ResourceLimits, SharedBudget,
};
use oncl_xml::{XmlDocument, XmlEventKind, XmlLimits};
use std::{
    io::{Cursor, Read},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
fn index(xml: &[u8]) -> Result<XmlDocument, ProcessingError> {
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone())?);
    let mut scope = budget.begin(limits, Arc::new(Control))?;
    let store = TemporaryStore::new(&std::env::temp_dir())?;
    XmlDocument::index(
        Source::sequential(&mut Cursor::new(xml), None),
        &XmlLimits::default(),
        &store,
        &mut scope,
    )
}
#[test]
fn duplicate_id_rejected() {
    for xml in [
        "<r><a Id='same'/><b Id='same'/></r>",
        "<r><a Id='a&amp;b'/><b ID='a&#38;b'/></r>",
        "<r><a xml:id=' a  b '/><b id='a b'/></r>",
        "<r Id='x'><a Id='x'/></r>",
    ] {
        assert!(index(xml.as_bytes()).is_err(), "{xml}");
    }
}
#[test]
fn attribute_crosses_chunk() {
    let prefix = "<r>";
    let tag = "<a Id='target' value='a&#38;b'/></r>";
    let xml = format!("{prefix}{}{tag}", " ".repeat(262144 - prefix.len() - 19));
    let mut doc = index(xml.as_bytes()).unwrap();
    let node = doc.lookup_id("target").unwrap().unwrap();
    let region = doc.node_region(&node).unwrap();
    assert_eq!(
        &xml.as_bytes()[region.offset as usize..region.end().unwrap() as usize],
        b"<a Id='target' value='a&#38;b'/>"
    );
    let mut events = doc.events();
    while let Some(event) = events.next_event().unwrap() {
        if event.kind == XmlEventKind::Start && event.name.as_ref().unwrap().local() == "a" {
            let value = event.attributes[1].value_region();
            assert_eq!(
                &xml.as_bytes()[value.offset as usize..value.end().unwrap() as usize],
                b"a&#38;b"
            );
        }
    }
}
#[test]
fn utf8_namespace_split() {
    let prefix = "<r>";
    let tag = "<p:а xmlns:p='urn:қазақ' Id='түйін'/></r>";
    let split = tag.find('қ').unwrap() + 1;
    let xml = format!("{prefix}{}{tag}", " ".repeat(262144 - prefix.len() - split));
    let mut doc = index(xml.as_bytes()).unwrap();
    assert!(doc.lookup_id("түйін").unwrap().is_some());
    let mut events = doc.events();
    let mut found = false;
    while let Some(event) = events.next_event().unwrap() {
        if event.kind == XmlEventKind::Start && event.name.as_ref().unwrap().local() == "а" {
            assert_eq!(event.name.as_ref().unwrap().namespace(), Some("urn:қазақ"));
            found = true;
        }
    }
    assert!(found);
}
#[test]
fn namespace_restore_and_attribute_spans() {
    let xml =
        b"<r xmlns:p='urn:outer'><a xmlns:p='urn:inner'><p:x a='a\r\nb&#10;c'/></a><p:x/></r>";
    let mut doc = index(xml).unwrap();
    let mut events = doc.events();
    let mut namespaces = Vec::new();
    while let Some(event) = events.next_event().unwrap() {
        if event.kind == XmlEventKind::Start && event.name.as_ref().unwrap().local() == "x" {
            let namespace = event.name.as_ref().unwrap().namespace().unwrap();
            assert_eq!(
                event.namespaces().find(|(prefix, _)| *prefix == "p"),
                Some(("p", namespace))
            );
            // Deliberate application-owned copies of borrowed strings are
            // supported; SDK-owned name/context cloning is not.
            namespaces.push(namespace.to_owned());
            if !event.attributes.is_empty() {
                let value = event.attributes[0].value_region();
                assert_eq!(
                    &xml[value.offset as usize..value.end().unwrap() as usize],
                    b"a\r\nb&#10;c"
                );
            }
        }
    }
    assert_eq!(namespaces, ["urn:inner", "urn:outer"]);
}
#[test]
fn merge_runs_compare_full_normalized_ids() {
    let mut xml = String::from("<r>");
    for i in 0..3100 {
        xml.push_str(&format!("<a Id='id-{i}'/>"));
    }
    xml.push_str("</r>");
    let mut doc = index(xml.as_bytes()).unwrap();
    for id in ["id-0", "id-1023", "id-2048", "id-3099"] {
        let node = doc.lookup_id(id).unwrap().unwrap();
        let region = doc.node_region(&node).unwrap();
        assert_eq!(
            &xml.as_bytes()[region.offset as usize..region.end().unwrap() as usize],
            format!("<a Id='{id}'/>").as_bytes()
        );
    }
    assert!(doc.lookup_id("absent").unwrap().is_none());
    xml.truncate(xml.len() - 4);
    xml.push_str("<a ID='id-0'/></r>");
    assert!(index(xml.as_bytes()).is_err());
}
#[test]
fn foreign_and_stale_handles_rejected() {
    let mut a = index(b"<a Id='x'/>").unwrap();
    let node = a.lookup_id("x").unwrap().unwrap();
    let b = index(b"<b Id='x'/>").unwrap();
    assert!(b.node_region(&node).is_err());
    drop(a);
    assert!(b.node_region(&node).is_err());
}
#[test]
fn malformed_and_external_entities_rejected() {
    for xml in [
        "<!DOCTYPE r SYSTEM 'file:///secret'><r/>",
        "<!DOCTYPE r [<!ENTITY e 'x'>]><r>&e;</r>",
        "<r>&unknown;</r>",
        "<r>&#0;</r>",
        "<r>]]></r>",
        "<r><!--a--b--></r>",
        "<r><x></r>",
        "<r/><r/>",
        "<p:r/>",
        "<r a='1' a='2'/>",
        "<r xmlns:p='u' xmlns:q='u' p:a='1' q:a='2'/>",
        "<r a:xmlns='u'/>",
        "<r>\u{0}</r>",
        "<r>\u{fffe}</r>",
        "<r/><?xml version='1.0'?>",
    ] {
        assert!(index(xml.as_bytes()).is_err(), "accepted {xml:?}");
    }
    assert!(index(b"<r>\xf0\x80\x80\x80</r>").is_err());
}
#[test]
fn comment_cdata_entity_utf8_and_prolog_baseline() {
    let mut doc = index("\u{feff}<?xml version='1.0' encoding='UTF-8'?><!--p--><r>қ&amp;<![CDATA[x]]]]><![CDATA[қ]]><?p x?></r><!--tail-->".as_bytes()).unwrap();
    let count = doc.token_count();
    let mut events = doc.events();
    let mut replayed = 0;
    while events.next_event().unwrap().is_some() {
        replayed += 1;
    }
    assert_eq!(count, replayed);
}
struct Cancel(Arc<AtomicBool>);
impl OperationControl for Cancel {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        if self.0.load(Ordering::Relaxed) {
            Err(ProcessingError::Cancelled)
        } else {
            Ok(())
        }
    }
}
#[test]
fn cleanup_cancel_quota_and_lease_retention() {
    let parent = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(parent.path()).unwrap();
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut scope = budget
        .begin(limits.clone(), Arc::new(Cancel(cancelled.clone())))
        .unwrap();
    let mut doc = XmlDocument::index(
        Source::sequential(&mut Cursor::new(b"<r Id='x'/>"), None),
        &XmlLimits::default(),
        &store,
        &mut scope,
    )
    .unwrap();
    drop(scope);
    assert!(budget.begin(limits.clone(), Arc::new(Control)).is_err());
    cancelled.store(true, Ordering::Relaxed);
    assert!(matches!(
        doc.lookup_id("x"),
        Err(ProcessingError::Cancelled)
    ));
    drop(doc);
    let mut scope = budget.begin(limits.clone(), Arc::new(Control)).unwrap();
    let root = std::fs::read_dir(parent.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    drop(scope);
    let tiny = ResourceLimits {
        temp_bytes: 20,
        ..limits.clone()
    };
    scope = budget.begin(tiny, Arc::new(Control)).unwrap();
    assert!(matches!(
        XmlDocument::index(
            Source::sequential(&mut Cursor::new(b"<r Id='x'/>"), None),
            &XmlLimits::default(),
            &store,
            &mut scope
        ),
        Err(ProcessingError::TempLimit)
    ));
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    drop(scope);
    drop(store);
    assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
}
#[test]
fn unknown_length_input_and_depth_limits_enforced() {
    let limits = ResourceLimits {
        input_bytes: 4,
        ..ResourceLimits::default()
    };
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    assert!(matches!(
        XmlDocument::index(
            Source::sequential(&mut Cursor::new(b"<root/>"), None),
            &XmlLimits::default(),
            &store,
            &mut scope
        ),
        Err(ProcessingError::InputLimit)
    ));
    let xml = format!("{}{}", "<a>".repeat(257), "</a>".repeat(257));
    assert!(index(xml.as_bytes()).is_err());
}
struct Short<'a>(&'a [u8]);
impl Read for Short<'_> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let n = b.len().min(self.0.len()).min(1);
        b[..n].copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
        Ok(n)
    }
}
#[test]
fn sequential_one_byte_reads_and_stable_source() {
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let mut bytes = b"<r xmlns:p='urn:u'><p:a Id='x'>\xd2\x9b&amp;</p:a></r>".to_vec();
    let mut doc = XmlDocument::index(
        Source::sequential(&mut Short(&bytes), None),
        &XmlLimits::default(),
        &store,
        &mut scope,
    )
    .unwrap();
    bytes.fill(0);
    let node = doc.lookup_id("x").unwrap().unwrap();
    let mut out = [0; 100];
    let n = doc.read_node(&node, 0, &mut out).unwrap();
    assert_eq!(&out[..n], b"<p:a Id='x'>\xd2\x9b&amp;</p:a>");
}
#[test]
#[ignore = "actual >4GiB structured release probe: cargo run --release -p oncl-xml --features testing --example indexed_xml_probe -- --out <scratch>"]
fn offset_over_4gib() {
    probe::run(std::env::temp_dir(), true).unwrap();
}
#[path = "support/indexed_probe.rs"]
mod probe;

#[test]
fn huge_attribute_is_a_validated_owner_bound_span() {
    let value = "қ&amp;".repeat(100000);
    let xml = format!("<r Id='x' data='{value}'/>");
    let mut doc = index(xml.as_bytes()).unwrap();
    let attribute = {
        let mut cursor = doc.events();
        let event = cursor.next_event().unwrap().unwrap();
        event.attributes[1].span()
    };
    assert_eq!(attribute.value_region().len, value.len() as u64);
    let mut bytes = vec![0; 262144];
    let mut offset = 0;
    while offset < attribute.value_region().len {
        let n = doc.read_attribute(&attribute, offset, &mut bytes).unwrap();
        assert_eq!(
            &bytes[..n],
            &value.as_bytes()[offset as usize..offset as usize + n]
        );
        offset += n as u64;
    }
    let mut other = index(b"<r data='other'/>").unwrap();
    assert!(other.read_attribute(&attribute, 0, &mut bytes).is_err());
    drop(doc);
    assert!(other.read_attribute(&attribute, 0, &mut bytes).is_err());
    assert!(index(b"<r data='bad&unknown;'/>").is_err());
    assert!(index(b"<r data='bad<markup'/>").is_err());
}

#[test]
fn namespace_identity_controls_id_limits_not_local_name_guess() {
    let xml = format!("<r xmlns:p='urn:ordinary' p:Id='{}'/>", "v".repeat(100000));
    assert!(index(xml.as_bytes()).is_ok());
    let xml = format!("<r Id='{}'/>", "v".repeat(1025));
    assert!(index(xml.as_bytes()).is_err());
}

#[test]
fn namespace_undeclaration_and_id_aliases() {
    let mut doc = index(b"<r xmlns='urn:outer' xmlns:p='urn:p'><x xmlns='' Id='a'><p:y xml:id=' b '/></x><z ID='c'/></r>").unwrap();
    assert!(doc.lookup_id("b").unwrap().is_some());
    let mut cursor = doc.events();
    let mut names = Vec::new();
    while let Some(event) = cursor.next_event().unwrap() {
        if event.kind == XmlEventKind::Start {
            let name = event.name.as_ref().unwrap();
            names.push((name.local().to_owned(), name.namespace().map(str::to_owned)));
        }
    }
    assert_eq!(
        names,
        [
            ("r".into(), Some("urn:outer".into())),
            ("x".into(), None),
            ("y".into(), Some("urn:p".into())),
            ("z".into(), Some("urn:outer".into()))
        ]
    );
}

struct ParseCancel {
    size: u64,
    calls: std::sync::atomic::AtomicUsize,
}
impl OperationControl for ParseCancel {
    fn checkpoint(&self, progress: Progress) -> Result<(), ProcessingError> {
        if progress.bytes_in == self.size && self.calls.fetch_add(1, Ordering::Relaxed) > 100 {
            Err(ProcessingError::Cancelled)
        } else {
            Ok(())
        }
    }
}
#[test]
fn cancellation_during_index_and_deadline_release_all_scratch() {
    let parent = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(parent.path()).unwrap();
    let root = std::fs::read_dir(parent.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let xml = format!("<r>{}</r>", "<a/>".repeat(10000));
    let mut scope = budget
        .begin(
            limits.clone(),
            Arc::new(ParseCancel {
                size: xml.len() as u64,
                calls: 0.into(),
            }),
        )
        .unwrap();
    assert!(matches!(
        XmlDocument::index(
            Source::sequential(&mut Cursor::new(xml.as_bytes()), Some(xml.len() as u64)),
            &XmlLimits::default(),
            &store,
            &mut scope
        ),
        Err(ProcessingError::Cancelled)
    ));
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    drop(scope);
    let limits = ResourceLimits {
        operation_timeout: std::time::Duration::from_nanos(1),
        ..limits
    };
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    assert!(matches!(
        XmlDocument::index(
            Source::sequential(&mut Cursor::new(b"<r/>"), None),
            &XmlLimits::default(),
            &store,
            &mut scope
        ),
        Err(ProcessingError::DeadlineExceeded)
    ));
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
}

#[test]
fn lexical_namespace_and_work_limits_are_explicit() {
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    for (xml, xml_limits) in [
        (
            "<r a='1' b='2'/>",
            XmlLimits {
                max_attributes: 1,
                ..XmlLimits::default()
            },
        ),
        (
            "<r xmlns:a='urn:a' xmlns:b='urn:b'/>",
            XmlLimits {
                max_namespaces: 1,
                ..XmlLimits::default()
            },
        ),
        (
            "<longname/>",
            XmlLimits {
                max_name_bytes: 2,
                ..XmlLimits::default()
            },
        ),
        (
            "<r><a/></r>",
            XmlLimits {
                max_work: 1,
                ..XmlLimits::default()
            },
        ),
    ] {
        let mut scope = budget.begin(limits.clone(), Arc::new(Control)).unwrap();
        assert!(
            XmlDocument::index(
                Source::sequential(&mut Cursor::new(xml.as_bytes()), None),
                &xml_limits,
                &store,
                &mut scope
            )
            .is_err()
        );
    }
    // Many '=' bytes in ordinary data do not turn into attribute cardinality.
    assert!(index(format!("<r data='{}'/>", "=".repeat(1000)).as_bytes()).is_ok());
}

#[test]
fn cached_events_and_empty_id_lookup_observe_cancellation() {
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let flag = Arc::new(AtomicBool::new(false));
    let mut scope = budget
        .begin(limits, Arc::new(Cancel(flag.clone())))
        .unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let mut doc = XmlDocument::index(
        Source::sequential(&mut Cursor::new(b"<r><a/></r>"), None),
        &XmlLimits::default(),
        &store,
        &mut scope,
    )
    .unwrap();
    flag.store(true, Ordering::Relaxed);
    assert!(matches!(
        doc.lookup_id("absent"),
        Err(ProcessingError::Cancelled)
    ));
    flag.store(false, Ordering::Relaxed);
    let mut cursor = doc.events();
    assert!(cursor.next_event().unwrap().is_some());
    flag.store(true, Ordering::Relaxed);
    assert!(matches!(
        cursor.next_event(),
        Err(ProcessingError::Cancelled)
    ));
}

#[test]
fn utf8_snapshot_rejects_conflicting_encoding_declaration() {
    assert!(index(b"<?xml version='1.0' encoding='UTF-16'?><r/>").is_err());
    assert!(index(b"<?xml version='1.0' encoding='utf-8'?><r/>").is_ok());
}

#[test]
fn declaration_requires_start_or_actual_bom() {
    for prefix in ["   ", " \t\n", "\r\n ", " ", "\u{feff} "] {
        let xml = format!("{prefix}<?xml version='1.0'?><r/>");
        assert!(index(xml.as_bytes()).is_err(), "accepted prefix {prefix:?}");
    }
    for prefix in ["", "\u{feff}"] {
        assert!(index(format!("{prefix}<?xml version='1.0'?><r/>").as_bytes()).is_ok());
    }
}

#[test]
fn entity_reference_state_validates_xml_characters_across_chunks() {
    let valid = [
        "&amp;",
        "&lt;",
        "&gt;",
        "&apos;",
        "&quot;",
        "&#65;",
        "&#x41;",
        "&#000000000000000000000000000000065;",
        "&#x000000000000000000000000000000041;",
        "&#9;",
        "&#10;",
        "&#13;",
        "&#xD7FF;",
        "&#xE000;",
        "&#xFFFD;",
        "&#x10000;",
        "&#x10FFFF;",
    ];
    for entity in valid {
        let prefix = "<r>";
        let xml = format!(
            "{prefix}{}{entity}</r>",
            " ".repeat(262144 - prefix.len() - 2)
        );
        assert!(index(xml.as_bytes()).is_ok(), "rejected {entity}");
        assert!(
            index(format!("<r data='{entity}'/>").as_bytes()).is_ok(),
            "attribute rejected {entity}"
        );
    }
    for entity in [
        "&;",
        "&AMP;",
        "&unknown;",
        "&#;",
        "&#x;",
        "&#X41;",
        "&#-1;",
        "&#0;",
        "&#11;",
        "&#xD800;",
        "&#xDFFF;",
        "&#xFFFE;",
        "&#xFFFF;",
        "&#x110000;",
        "&#4294967296;",
        "&#x100000000;",
        "&#99999999999999999999999999999999;",
        "&#xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;",
        "&amp",
        "&#65",
        "&am&amp;",
    ] {
        assert!(
            index(format!("<r>{entity}</r>").as_bytes()).is_err(),
            "accepted {entity}"
        );
        assert!(
            index(format!("<r data='{entity}'/>").as_bytes()).is_err(),
            "attribute accepted {entity}"
        );
        assert!(
            index(format!("<r xmlns:p='{entity}'/>").as_bytes()).is_err(),
            "namespace accepted {entity}"
        );
        assert!(
            index(format!("<r Id='{entity}'/>").as_bytes()).is_err(),
            "ID accepted {entity}"
        );
    }
}

#[test]
fn retained_attribute_span_releases_document_metadata_and_admission() {
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut scope = budget
        .begin(limits.clone(), Arc::new(Cancel(cancelled.clone())))
        .unwrap();
    let xml = format!(
        "<r xmlns:p='urn:{}' p:data='raw&amp;bytes'/>",
        "namespace".repeat(1000)
    );
    let mut doc = XmlDocument::index(
        Source::sequential(&mut Cursor::new(xml.as_bytes()), None),
        &XmlLimits::default(),
        &store,
        &mut scope,
    )
    .unwrap();
    let span = {
        let mut cursor = doc.events();
        let event = cursor.next_event().unwrap().unwrap();
        assert!(event.attributes[0].name.namespace().unwrap().len() > 8000);
        event.attributes[0].span()
    };
    drop(scope);
    assert!(budget.begin(limits.clone(), Arc::new(Control)).is_err());
    let mut bytes = [0; 32];
    cancelled.store(true, Ordering::Relaxed);
    assert!(matches!(
        doc.read_attribute(&span, 0, &mut bytes),
        Err(ProcessingError::Cancelled)
    ));
    cancelled.store(false, Ordering::Relaxed);
    let n = doc.read_attribute(&span, 0, &mut bytes).unwrap();
    assert_eq!(&bytes[..n], b"raw&amp;bytes");
    drop(doc);
    // The still-retained opaque span holds only identity/Region, not an
    // admission lease or the element's large expanded namespace strings.
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let mut other = XmlDocument::index(
        Source::sequential(&mut Cursor::new(b"<r/>"), None),
        &XmlLimits::default(),
        &store,
        &mut scope,
    )
    .unwrap();
    assert!(other.read_attribute(&span, 0, &mut bytes).is_err());
}

#[test]
fn consumed_overflow_is_retained_and_terminal() {
    let limits = ResourceLimits {
        input_bytes: 3,
        ..ResourceLimits::default()
    };
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    assert!(matches!(
        XmlDocument::index(
            Source::sequential(&mut Cursor::new(b"<r/>"), None),
            &XmlLimits::default(),
            &store,
            &mut scope,
        ),
        Err(ProcessingError::InputLimit)
    ));
    assert_eq!(scope.progress().bytes_in, 4);
    struct MustNotRead;
    impl Read for MustNotRead {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            panic!("terminal operation must not consume more input")
        }
    }
    assert!(matches!(
        XmlDocument::index(
            Source::sequential(&mut MustNotRead, None),
            &XmlLimits::default(),
            &store,
            &mut scope,
        ),
        Err(ProcessingError::InputLimit)
    ));
}

#[test]
fn authentic_snapshot_index_does_not_double_charge() {
    use oncl_pki::io::{FrozenInput, Region};
    let xml = b"<r/>";
    let limits = ResourceLimits {
        input_bytes: xml.len() as u64,
        ..ResourceLimits::default()
    };
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let mut frozen = FrozenInput::capture(
        Source::sequential(&mut Cursor::new(xml), None),
        &store,
        &mut scope,
    )
    .unwrap();
    let mut reader = frozen
        .reader(
            &[Region {
                offset: 0,
                len: xml.len() as u64,
            }],
            &scope,
        )
        .unwrap();
    let doc =
        XmlDocument::index(reader.source(), &XmlLimits::default(), &store, &mut scope).unwrap();
    assert_eq!(doc.len(), xml.len() as u64);
    assert_eq!(scope.progress().bytes_in, xml.len() as u64);
}

#[test]
fn cancelled_read_retains_consumption() {
    struct CancelRead(Arc<AtomicBool>);
    impl Read for CancelRead {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            out[..4].copy_from_slice(b"<r/>");
            self.0.store(true, Ordering::Relaxed);
            Ok(4)
        }
    }
    let flag = Arc::new(AtomicBool::new(false));
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget
        .begin(limits, Arc::new(Cancel(flag.clone())))
        .unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    assert!(matches!(
        XmlDocument::index(
            Source::sequential(&mut CancelRead(flag), None),
            &XmlLimits::default(),
            &store,
            &mut scope,
        ),
        Err(ProcessingError::Cancelled)
    ));
    assert_eq!(scope.progress().bytes_in, 4);
}

#[test]
fn foreign_snapshot_rejected_before_source_io() {
    use oncl_pki::io::{FrozenInput, Region};
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits.clone(), Arc::new(Control)).unwrap();
    let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
    let mut frozen = FrozenInput::capture(
        Source::sequential(&mut Cursor::new(b"<r/>"), None),
        &store,
        &mut scope,
    )
    .unwrap();
    let mut reader = frozen
        .reader(&[Region { offset: 0, len: 4 }], &scope)
        .unwrap();
    let other_budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut other_scope = other_budget.begin(limits, Arc::new(Control)).unwrap();
    assert!(matches!(
        XmlDocument::index(
            reader.source(),
            &XmlLimits::default(),
            &store,
            &mut other_scope,
        ),
        Err(ProcessingError::InvalidInput(_))
    ));
    assert_eq!(other_scope.progress().bytes_in, 0);
    let mut bytes = [0; 4];
    reader.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"<r/>");
}

#[test]
fn index_metadata_is_live_ram_once_plus_the_actual_capture_buffer() {
    let xml_limits = XmlLimits {
        max_depth: 1,
        max_markup_bytes: 32,
        max_namespace_bytes: 64,
        ..Default::default()
    };
    let index_bound = 12 * 1024 * 1024 + 32 * 3 + 64 + 8192;
    let capture_header = (std::mem::size_of::<oncl_pki::io::StagedArtifact>() + 512) as u64;
    for short in [false, true] {
        let limits = ResourceLimits {
            memory_bytes: index_bound + oncl_pki::resource::IO_CHUNK_BYTES as u64 + capture_header
                - u64::from(short),
            ..Default::default()
        };
        let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
        let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
        let store = TemporaryStore::new(&std::env::temp_dir()).unwrap();
        let result = XmlDocument::index(
            Source::sequential(&mut Cursor::new(b"<r/>"), None),
            &xml_limits,
            &store,
            &mut scope,
        );
        if short {
            assert!(matches!(
                result,
                Err(ProcessingError::MemoryLimit | ProcessingError::MetadataLimit)
            ));
        } else {
            assert!(
                result.is_ok(),
                "one index metadata reservation and actual capture buffer must fit: {:?}",
                result.err()
            );
        }
    }
}
