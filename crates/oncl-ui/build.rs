//! Compiles the dialogs with their Kazakh and Russian translations bundled.

use slint_build::{CompilerConfiguration, DefaultTranslationContext};

fn main() {
    let config = CompilerConfiguration::new()
        .with_bundled_translations("po")
        // The catalogs key strings by text alone: a string shared by both dialogs is
        // translated once.
        .with_default_translation_context(DefaultTranslationContext::None);
    if let Err(e) = slint_build::compile_with_config("ui/dialogs.slint", config) {
        panic!("{e}");
    }
}
