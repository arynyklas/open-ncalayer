//! Windows of the tests without a display: Slint's software renderer in memory, on the
//! calling thread (Slint's platform is per thread). There is no event loop.

use std::cell::RefCell;
use std::rc::Rc;

use slint::PlatformError;
use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
use slint::platform::{Platform, WindowAdapter};

/// The last window created on the thread.
pub(crate) type Last = Rc<RefCell<Option<Rc<MinimalSoftwareWindow>>>>;

struct Offscreen(Last);

impl Platform for Offscreen {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, PlatformError> {
        let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
        self.0.replace(Some(Rc::clone(&window)));
        Ok(window)
    }
}

/// Makes this thread's windows offscreen; returns where the last one created is kept.
pub(crate) fn install() -> Last {
    let last = Last::default();
    slint::platform::set_platform(Box::new(Offscreen(Rc::clone(&last))))
        .expect("the thread has no platform yet");
    last
}
