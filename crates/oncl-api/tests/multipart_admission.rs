#![cfg(feature = "server")]
use axum::body::Bytes;
use futures_util::{StreamExt, stream};
use oncl_api::multipart::BoundedMultipart;
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

fn source(
    data: Vec<u8>,
    size: usize,
    seen: Arc<AtomicUsize>,
) -> impl futures_util::Stream<Item = Result<Bytes, io::Error>> + Send {
    stream::iter(
        data.chunks(size)
            .map(Bytes::copy_from_slice)
            .collect::<Vec<_>>(),
    )
    .map(move |b| {
        seen.fetch_add(b.len(), Ordering::SeqCst);
        Ok(b)
    })
}
fn part(name: &str, value: &str) -> String {
    format!("--b\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n")
}

#[tokio::test]
async fn header_budget_restored_after_data_and_empty_fields() {
    for size in [1, 3, 4096, 65536] {
        for first in ["".to_owned(), "x".repeat(20_000)] {
            let seen = Arc::new(AtomicUsize::new(0));
            let mut data = part("document", &first);
            data.push_str("--b\r\nContent-Disposition: form-data; name=\"");
            data.push_str(&"a".repeat(100_000));
            let mut parser = BoundedMultipart::new(
                source(data.into_bytes(), size, seen.clone()),
                "b",
                200_000,
                &["document"],
            )
            .unwrap();
            let field = parser.next_field().await.unwrap().unwrap();
            assert_eq!(field.name(), Some("document"));
            parser.admit_data();
            assert_eq!(field.bytes().await.unwrap().len(), first.len());
            assert!(parser.next_field().await.is_err());
            // One original transport frame is retained, not an entire document.
            assert!(seen.load(Ordering::SeqCst) < first.len() + 90_000);
        }
    }
}

#[tokio::test]
async fn dropped_field_cannot_skip_unbounded_data_under_header_mode() {
    let mut data = part("document", &"x".repeat(100_000));
    data.push_str("--b--\r\n");
    let seen = Arc::new(AtomicUsize::new(0));
    let mut parser = BoundedMultipart::new(
        source(data.into_bytes(), 4096, seen.clone()),
        "b",
        200_000,
        &["document"],
    )
    .unwrap();
    drop(parser.next_field().await.unwrap().unwrap());
    assert!(parser.next_field().await.is_err());
    assert!(seen.load(Ordering::SeqCst) < 24_000);
}

#[tokio::test]
async fn empty_part_flood_is_finite_and_exact_part_limit_can_finish() {
    for count in [128, 129, 10_000] {
        let mut data = part("document", "").repeat(count);
        data.push_str("--b--\r\n");
        let seen = Arc::new(AtomicUsize::new(0));
        let mut parser = BoundedMultipart::new(
            source(data.into_bytes(), 7, seen.clone()),
            "b",
            1_000_000,
            &["document"],
        )
        .unwrap();
        let mut accepted = 0;
        let result = loop {
            match parser.next_field().await {
                Ok(Some(field)) => {
                    parser.admit_data();
                    field.bytes().await.unwrap();
                    accepted += 1;
                }
                Ok(None) => break Ok(()),
                Err(error) => break Err(error),
            }
        };
        assert_eq!(accepted, 128);
        assert_eq!(result.is_ok(), count == 128);
        assert!(seen.load(Ordering::SeqCst) < 10_000);
    }
}

#[tokio::test]
async fn legal_large_transport_frame_is_not_a_document_limit() {
    let mut data = part("document", &"x".repeat(200_000));
    data.push_str("--b--\r\n");
    let mut parser = BoundedMultipart::new(
        source(data.into_bytes(), 65536, Arc::new(AtomicUsize::new(0))),
        "b",
        300_000,
        &["document"],
    )
    .unwrap();
    let field = parser.next_field().await.unwrap().unwrap();
    parser.admit_data();
    assert_eq!(field.bytes().await.unwrap().len(), 200_000);
    assert!(parser.next_field().await.unwrap().is_none());
}

#[tokio::test]
async fn metadata_first_installs_exact_field_names_and_cardinality() {
    let data = format!(
        "{}{}{}--b--\r\n",
        part("metadata", "{}"),
        part("doc-a", "abc"),
        part("unexpected", "secret")
    );
    let mut parser = BoundedMultipart::new(
        source(data.into_bytes(), 1, Arc::new(AtomicUsize::new(0))),
        "b",
        4096,
        &["metadata"],
    )
    .unwrap();
    let metadata = parser.next_field().await.unwrap().unwrap();
    parser.admit_data();
    assert_eq!(metadata.bytes().await.unwrap(), &b"{}"[..]);
    parser.install_fields(&["doc-a"], 1).unwrap();
    let document = parser.next_field().await.unwrap().unwrap();
    assert_eq!(document.name(), Some("doc-a"));
    parser.admit_data();
    assert_eq!(document.bytes().await.unwrap(), &b"abc"[..]);
    assert!(parser.next_field().await.is_err());
    assert!(parser.install_fields(&["unexpected"], 2).is_err());
}
