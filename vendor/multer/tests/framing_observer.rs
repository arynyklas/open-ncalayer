use bytes::Bytes;
use futures_util::stream;
use multer::{Constraints, FramingObserver, Multipart};
use std::{
    io,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
struct Counter {
    bytes: AtomicU64,
    limit: u64,
}
impl FramingObserver for Counter {
    fn observe(&self, bytes: u64) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let total = self.bytes.fetch_add(bytes, Ordering::SeqCst) + bytes;
        if total > self.limit {
            Err(io::Error::other("framing resource refused").into())
        } else {
            Ok(())
        }
    }
}
fn source(data: &[u8], chunk: usize) -> impl futures_util::Stream<Item = Result<Bytes, io::Error>> + Send + use<> {
    let chunks = data
        .chunks(chunk)
        .map(Bytes::copy_from_slice)
        .collect::<Vec<_>>()
        .into_iter();
    stream::unfold(chunks, |mut chunks| async move {
        tokio::task::yield_now().await;
        chunks.next().map(|bytes| (Ok(bytes), chunks))
    })
}
#[tokio::test]
async fn raw_framing_is_exact_without_payload_or_readahead_debit() {
    let data=b"preamble\r\n--b \t\r\nContent-Disposition: form-data; name=\"first\"\r\nX-Raw:  a  b\r\n\r\nabc\r\n--b\r\nContent-Disposition: form-data; name=\"empty\"\r\n\r\n\r\n--b--\r\nEPILOGUE";
    let expected = (data.len() - 3 - b"\r\nEPILOGUE".len()) as u64;
    for split in [1, 2, 3, 7, 4096, 65536] {
        let counter = Arc::new(Counter {
            bytes: AtomicU64::new(0),
            limit: expected,
        });
        let mut parser = Multipart::with_constraints(
            source(data, split),
            "b",
            Constraints::new().framing_observer(counter.clone()),
        );
        assert_eq!(
            parser.next_field().await.unwrap().unwrap().bytes().await.unwrap(),
            &b"abc"[..]
        );
        assert_eq!(
            parser.next_field().await.unwrap().unwrap().bytes().await.unwrap(),
            &b""[..]
        );
        assert!(parser.next_field().await.unwrap().is_none());
        assert_eq!(counter.bytes.load(Ordering::SeqCst), expected);
    }
}
#[tokio::test]
async fn partial_and_complete_headers_refuse_before_unsent_body() {
    use futures_util::StreamExt;
    for ending in ["", "\r\n\r\n"] {
        let data = format!(
            "--b\r\nContent-Disposition: form-data; name=\"first\"\r\nX-Raw: {}{}",
            "x".repeat(1024),
            ending
        );
        let input = source(data.as_bytes(), 7).chain(stream::pending());
        let counter = Arc::new(Counter {
            bytes: AtomicU64::new(0),
            limit: 512,
        });
        let mut parser = Multipart::with_constraints(input, "b", Constraints::new().framing_observer(counter.clone()));
        let result = tokio::time::timeout(Duration::from_secs(1), parser.next_field())
            .await
            .unwrap();
        assert!(result.is_err());
        assert!(counter.bytes.load(Ordering::SeqCst) > 512);
    }
}
#[tokio::test]
async fn exact_limit_accepts_but_final_boundary_n_plus_one_is_refused() {
    let data = b"--b\r\nContent-Disposition: form-data; name=\"first\"\r\n\r\nabc\r\n--b--\r\n";
    let exact = (data.len() - 3 - 2) as u64;
    for limit in [exact, exact - 1] {
        let counter = Arc::new(Counter {
            bytes: AtomicU64::new(0),
            limit,
        });
        let mut parser =
            Multipart::with_constraints(source(data, 1), "b", Constraints::new().framing_observer(counter));
        assert_eq!(
            parser.next_field().await.unwrap().unwrap().bytes().await.unwrap(),
            &b"abc"[..]
        );
        assert_eq!(parser.next_field().await.is_ok(), limit == exact);
    }
}
