//! The module's exports and the core it asks, on `wasm32`.

use oncl_pdk::abi::{CoreBundles, CoreModules, ErrorCode, Os, Window};
use oncl_pdk::host::{self, Level};
use oncl_pdk::{Request, core};

/// The core, through the `core_*` host functions. They fail only in a core that does not
/// serve its modules, which is the module's failure: the connection is dropped.
struct Host;

impl crate::Core for Host {
    fn modules(&self) -> CoreModules {
        core::modules().expect("core_modules")
    }

    fn bundles(&self) -> CoreBundles {
        core::bundles().expect("core_bundles")
    }

    fn install_bundle(&self, symname: &str) -> Option<bool> {
        match core::install_bundle(symname) {
            Ok(offered) => Some(offered),
            Err(e) if e.code == ErrorCode::Invalid => None,
            Err(e) => panic!("core_install_bundle: {e}"),
        }
    }

    fn open_window(&self, window: Window) {
        core::open_window(window).expect("core_open_window");
    }

    fn os(&self) -> Os {
        host::platform().expect("platform").os
    }
}

fn handle(request: &Request) -> String {
    crate::handle(&Host, &request.text).unwrap_or_else(|exception| {
        let _ = host::log(
            Level::Error,
            &format!("accessory request failed: {exception}"),
        );
        crate::failure(&exception)
    })
}

oncl_pdk::plugin!(handle);
