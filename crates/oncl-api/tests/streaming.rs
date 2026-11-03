#![cfg(feature = "server")]
use axum::body::Bytes;
use futures_util::stream;
use oncl_api::multipart::BoundedMultipart;
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

fn chunks(
    data: &[u8],
    size: usize,
) -> impl futures_util::Stream<Item = Result<Bytes, io::Error>> + Send + use<> {
    stream::iter(
        data.chunks(size)
            .map(|b| Ok(Bytes::copy_from_slice(b)))
            .collect::<Vec<_>>(),
    )
}

#[tokio::test]
async fn unknown_length_and_split_boundaries() {
    let data = b"--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{}\r\n--b\r\nContent-Disposition: form-data; name=\"document\"\r\n\r\nabc\0def\r\n--b--\r\n";
    for split in [1, 2, 3, 7, 31, 4096] {
        let mut parser =
            BoundedMultipart::new(chunks(data, split), "b", 4096, &["metadata", "document"])
                .unwrap();
        let first = parser.next_field().await.unwrap().unwrap();
        assert_eq!(first.name(), Some("metadata"));
        parser.admit_data();
        assert_eq!(first.bytes().await.unwrap(), &b"{}"[..]);
        let second = parser.next_field().await.unwrap().unwrap();
        assert_eq!(second.name(), Some("document"));
        parser.admit_data();
        assert_eq!(second.bytes().await.unwrap(), &b"abc\0def"[..]);
        assert!(parser.next_field().await.unwrap().is_none());
    }
}

#[tokio::test]
async fn oversized_split_headers_are_rejected_before_unbounded_buffering() {
    for prefix in ["Content-Disposition: form-data; name=\"", "X-Unknown: "] {
        let bytes_read = Arc::new(AtomicUsize::new(0));
        let count = bytes_read.clone();
        let data = format!("--b\r\n{prefix}{}", "a".repeat(1_000_000));
        let source = stream::iter(
            data.into_bytes()
                .chunks(7)
                .map(|b| b.to_vec())
                .collect::<Vec<_>>(),
        )
        .map(move |b| {
            count.fetch_add(b.len(), Ordering::SeqCst);
            Ok::<_, io::Error>(Bytes::from(b))
        });
        let mut parser = BoundedMultipart::new(source, "b", 2_000_000, &["metadata"]).unwrap();
        assert!(parser.next_field().await.is_err());
        assert!(
            bytes_read.load(Ordering::SeqCst) < 20_000,
            "header admission must fail before entire source is consumed"
        );
    }
}

#[tokio::test]
async fn continuously_ready_document_stream_remains_incremental() {
    use futures_util::StreamExt;
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    let mut data = b"--b\r\nContent-Disposition: form-data; name=\"document\"\r\n\r\n".to_vec();
    data.extend(std::iter::repeat_n(b'x', 1_000_000));
    data.extend_from_slice(b"\r\n--b--\r\n");
    let source = chunks(&data, 4096).map(move |b| {
        seen.fetch_add(b.as_ref().unwrap().len(), Ordering::SeqCst);
        b
    });
    let mut parser = BoundedMultipart::new(source, "b", 2_000_000, &["document"]).unwrap();
    let mut field = parser.next_field().await.unwrap().unwrap();
    parser.admit_data();
    let first = field.chunk().await.unwrap().unwrap();
    assert!(!first.is_empty());
    assert!(
        count.load(Ordering::SeqCst) < 32_768,
        "ready stream must not be collected by parser polling"
    );
    let mut total = first.len();
    while let Some(bytes) = field.chunk().await.unwrap() {
        total += bytes.len();
    }
    assert_eq!(total, 1_000_000);
    drop(field);
    assert!(parser.next_field().await.unwrap().is_none());
}

#[tokio::test]
async fn actual_framing_n_plus_one_is_rejected() {
    let data = b"--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{}\r\n--b--\r\n";
    let mut parser = BoundedMultipart::new(chunks(data, 1), "b", 60, &["metadata"]).unwrap();
    let result = async {
        while let Some(field) = parser.next_field().await? {
            field.bytes().await?;
        }
        Ok::<_, multer::Error>(())
    }
    .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn unknown_roles_and_excessive_header_count_are_rejected() {
    let data =
        b"--b\r\nContent-Disposition: form-data; name=\"key-path\"\r\n\r\nprivate\r\n--b--\r\n";
    let mut parser = BoundedMultipart::new(chunks(data, 1), "b", 4096, &["metadata"]).unwrap();
    assert!(parser.next_field().await.is_err());
    let data = format!(
        "--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n{}\r\n{{}}\r\n--b--\r\n",
        "X-A: b\r\n".repeat(100)
    );
    let mut parser =
        BoundedMultipart::new(chunks(data.as_bytes(), 1), "b", 4096, &["metadata"]).unwrap();
    assert!(parser.next_field().await.is_err());
}

#[test]
fn boundary_is_bounded_before_parser_allocation() {
    for boundary in ["".to_owned(), "a".repeat(71), "bad\r\nboundary".to_owned()] {
        assert!(BoundedMultipart::new(chunks(b"", 1), &boundary, 4096, &["metadata"]).is_err());
    }
}

use futures_util::StreamExt;
