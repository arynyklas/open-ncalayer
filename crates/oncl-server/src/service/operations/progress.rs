use oncl_pki::resource::{ProcessingError, Progress};
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

/// One latest fixed-size snapshot, not a queue of callbacks. Thread registration
/// identifies only checkpoint provenance, never permissions or SDK authority.
pub(in crate::service) struct ProgressHub {
    native: Mutex<Option<std::thread::ThreadId>>,
    sender: watch::Sender<Progress>,
}
pub(super) struct NativeProgress {
    hub: Arc<ProgressHub>,
}
impl ProgressHub {
    pub(super) fn channel() -> (Arc<Self>, watch::Receiver<Progress>) {
        let (sender, receiver) = watch::channel(Progress::default());
        (
            Arc::new(Self {
                native: Mutex::new(None),
                sender,
            }),
            receiver,
        )
    }
    pub(super) fn native(self: &Arc<Self>) -> Result<NativeProgress, ProcessingError> {
        let mut native = self
            .native
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if native.is_some() {
            return Err(ProcessingError::InvalidInput(
                "progress producer already active",
            ));
        }
        *native = Some(std::thread::current().id());
        Ok(NativeProgress { hub: self.clone() })
    }
    pub(in crate::service) fn publish(&self, progress: Progress) {
        let native = self
            .native
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *native != Some(std::thread::current().id()) {
            return;
        }
        // Response/socket checkpoints must not turn reporting its own framing
        // bytes into an endless stream of self-generated progress.
        self.sender.send_if_modified(|previous| {
            if *previous == progress {
                false
            } else {
                *previous = progress;
                true
            }
        });
    }
}
impl Drop for NativeProgress {
    fn drop(&mut self) {
        *self
            .hub
            .native
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oncl_pki::resource::Progress;
    #[test]
    fn native_checkpoints_coalesce_without_network_feedback() {
        let (hub, mut receiver) = ProgressHub::channel();
        hub.publish(Progress {
            bytes_in: 1,
            bytes_out: 0,
        });
        assert!(!receiver.has_changed().unwrap());
        let native = hub.native().unwrap();
        hub.publish(Progress {
            bytes_in: 1,
            bytes_out: 2,
        });
        hub.publish(Progress {
            bytes_in: 3,
            bytes_out: 4,
        });
        assert_eq!(
            *receiver.borrow_and_update(),
            Progress {
                bytes_in: 3,
                bytes_out: 4
            }
        );
        hub.publish(Progress {
            bytes_in: 3,
            bytes_out: 4,
        });
        assert!(!receiver.has_changed().unwrap());
        let network = hub.clone();
        std::thread::spawn(move || {
            network.publish(Progress {
                bytes_in: 3,
                bytes_out: 100,
            })
        })
        .join()
        .unwrap();
        assert!(!receiver.has_changed().unwrap());
        drop(native);
        hub.publish(Progress {
            bytes_in: 3,
            bytes_out: 200,
        });
        assert!(!receiver.has_changed().unwrap());
    }
    #[test]
    fn native_registration_does_not_broaden_or_replace_an_active_producer() {
        let (hub, _) = ProgressHub::channel();
        let native = hub.native().unwrap();
        assert!(hub.native().is_err());
        drop(native);
        assert!(hub.native().is_ok());
    }
}
