//! Embeds the built-in modules' guests (`SOURCES`), as the daemon does.

use std::path::Path;

fn main() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    if let Err(e) = oncl_builtins_build::embed(&workspace) {
        panic!("the built-in modules: {e}");
    }
}
