use oncl_api::{
    error::ApiError,
    server::{HashHost, RequestMetadata, ResponseFuture},
};
use oncl_pki::resource::Deadline;
use oncl_server::service::{ResponseDelivery, ServiceHost};
use std::{
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// Transparent observer: responses and all authority/body/hash work are produced
// by the real ServiceHost. No alternate endpoint, digest or control is fabricated.
pub struct ObserveDelivery {
    pub host: Arc<ServiceHost>,
    pub ready: Mutex<Option<tokio::sync::oneshot::Sender<Deadline>>>,
}
impl HashHost for ObserveDelivery {
    fn hash(&self, metadata: RequestMetadata, body: axum::body::Body) -> ResponseFuture {
        let future = self.host.hash(metadata, body);
        let ready = self.ready.lock().unwrap().take();
        Box::pin(async move {
            let response = future.await?;
            let deadline = response
                .extensions()
                .get::<ResponseDelivery>()
                .expect("real hash delivery state")
                .deadline();
            if let Some(ready) = ready {
                let _ = ready.send(deadline);
            }
            Ok::<_, ApiError>(response)
        })
    }
    fn health(&self, metadata: RequestMetadata) -> ResponseFuture {
        self.host.health(metadata)
    }
    fn operations(&self, metadata: RequestMetadata, body: axum::body::Body) -> ResponseFuture {
        self.host.operations(metadata, body)
    }
    fn batch(&self, metadata: RequestMetadata, body: axum::body::Body) -> ResponseFuture {
        self.host.batch(metadata, body)
    }
    fn openapi(&self, metadata: RequestMetadata) -> ResponseFuture {
        self.host.openapi(metadata)
    }
}
pub struct WriteGate {
    open: AtomicBool,
    entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    waker: Mutex<Option<Waker>>,
}
impl WriteGate {
    pub fn new() -> (Arc<Self>, tokio::sync::oneshot::Receiver<()>) {
        let (entered, ready) = tokio::sync::oneshot::channel();
        (
            Arc::new(Self {
                open: AtomicBool::new(false),
                entered: Mutex::new(Some(entered)),
                waker: Mutex::new(None),
            }),
            ready,
        )
    }
    pub fn release(&self) {
        self.open.store(true, Ordering::Release);
        if let Some(waker) = self.waker.lock().unwrap().take() {
            waker.wake();
        }
    }
    fn permits_write(&self, cx: &Context<'_>) -> bool {
        if self.open.load(Ordering::Acquire) {
            return true;
        }
        *self.waker.lock().unwrap() = Some(cx.waker().clone());
        if let Some(entered) = self.entered.lock().unwrap().take() {
            let _ = entered.send(());
        }
        self.open.load(Ordering::Acquire)
    }
}
// Reads and writes delegate to an actual accepted socket. Real encoded headers
// pass first; only body write readiness is barred, with Hyper owning its Bytes.
pub struct GatedSocket {
    socket: tokio::net::TcpStream,
    gate: Arc<WriteGate>,
    header_left: Option<usize>,
}
impl GatedSocket {
    pub fn new(socket: tokio::net::TcpStream, gate: Arc<WriteGate>) -> Self {
        Self {
            socket,
            gate,
            header_left: None,
        }
    }
}
impl AsyncRead for GatedSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().socket).poll_read(cx, buffer)
    }
}
impl AsyncWrite for GatedSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let remaining = *this.header_left.get_or_insert_with(|| {
            buffer
                .windows(4)
                .position(|part| part == b"\r\n\r\n")
                .expect("Hyper's real encoded header block")
                + 4
        });
        if remaining != 0 {
            let result =
                Pin::new(&mut this.socket).poll_write(cx, &buffer[..remaining.min(buffer.len())]);
            if let Poll::Ready(Ok(written)) = result {
                this.header_left = Some(remaining - written);
            }
            return result;
        }
        if !this.gate.permits_write(cx) {
            return Poll::Pending;
        }
        Pin::new(&mut this.socket).poll_write(cx, buffer)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.gate.permits_write(cx) {
            return Poll::Pending;
        }
        Pin::new(&mut this.socket).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.gate.permits_write(cx) {
            return Poll::Pending;
        }
        Pin::new(&mut this.socket).poll_shutdown(cx)
    }
}
