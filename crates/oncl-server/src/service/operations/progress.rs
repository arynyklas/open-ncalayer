use oncl_pki::resource::{ProcessingError, Progress};
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

/// Position inside a closed batch; coalesced like byte progress (latest wins).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::service) struct ItemCursor {
    pub total: u32,
    pub finished: u32,
    pub current: Option<u32>,
}
/// The latest fixed-size state of one invocation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::service) struct Snapshot {
    pub progress: Progress,
    pub items: Option<ItemCursor>,
}
/// One latest fixed-size snapshot, not a queue of callbacks. Thread registration
/// identifies only checkpoint provenance, never permissions or SDK authority.
pub(in crate::service) struct ProgressHub {
    native: Mutex<Option<std::thread::ThreadId>>,
    sender: watch::Sender<Snapshot>,
}
pub(super) struct NativeProgress {
    hub: Arc<ProgressHub>,
}
impl ProgressHub {
    pub(super) fn channel() -> (Arc<Self>, watch::Receiver<Snapshot>) {
        let (sender, receiver) = watch::channel(Snapshot::default());
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
            if previous.progress == progress {
                false
            } else {
                previous.progress = progress;
                true
            }
        });
    }
    /// Batch position, from the registered native thread only.
    pub(super) fn publish_items(&self, cursor: ItemCursor) {
        let native = self
            .native
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *native != Some(std::thread::current().id()) {
            return;
        }
        self.sender.send_if_modified(|previous| {
            if previous.items == Some(cursor) {
                false
            } else {
                previous.items = Some(cursor);
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
            receiver.borrow_and_update().progress,
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
