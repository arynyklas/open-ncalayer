//! A window with the program's own secret fields, filled with a throwaway secret, for
//! `scripts/uia-secret-probe.ps1`: it reads the window with UI Automation and fails when the
//! secret is in any of the properties an accessibility client can read.
//!
//! `uia_secret_probe dialogs | workspace-sign | workspace-inspect | workspace-plugins`

use slint::{ComponentHandle, ModelRc, VecModel};

slint::slint! {
    export { PasswordDialog, StorageDialog, StorageRow, CsrDialog, ImportDialog, WorkspaceWindow, SigningState, PluginsState } from "../ui/dialogs.slint";
}

/// What the script looks for; never a real secret.
const SECRET: &str = "UIA-probe-secret-4417";

fn main() -> Result<(), slint::PlatformError> {
    let mode = std::env::args().nth(1).unwrap_or_default();
    match mode.as_str() {
        "dialogs" => {
            let password = PasswordDialog::new()?;
            password.set_password(SECRET.into());
            password.show()?;

            let storage = StorageDialog::new()?;
            storage.set_storages(ModelRc::new(VecModel::from(vec![
                StorageRow {
                    label: "File".into(),
                    supported: true,
                    token: false,
                },
                StorageRow {
                    label: "Token".into(),
                    supported: true,
                    token: true,
                },
            ])));
            storage.set_selected(0);
            storage.set_password(SECRET.into());
            storage.show()?;

            let csr = CsrDialog::new()?;
            csr.set_ask_password(true);
            csr.set_password(SECRET.into());
            csr.set_confirmation(SECRET.into());
            csr.show()?;

            let import = ImportDialog::new()?;
            import.set_password(SECRET.into());
            import.set_confirmation(SECRET.into());
            import.show()?;

            slint::run_event_loop()
        }
        "workspace-sign" | "workspace-inspect" | "workspace-plugins" => {
            let ui = WorkspaceWindow::new()?;
            match mode.as_str() {
                "workspace-sign" => {
                    ui.set_section(1);
                    ui.global::<SigningState>().set_step(1);
                    ui.global::<SigningState>().set_password(SECRET.into());
                }
                "workspace-inspect" => {
                    ui.set_section(7);
                    ui.set_inspect_kind(2);
                    ui.set_inspect_password(SECRET.into());
                }
                _ => {
                    ui.set_section(8);
                    ui.global::<PluginsState>().set_step(2);
                    ui.global::<PluginsState>()
                        .set_password_label("Key store password".into());
                    ui.global::<PluginsState>().set_password(SECRET.into());
                }
            }
            ui.show()?;
            slint::run_event_loop()
        }
        _ => {
            eprintln!(
                "uia_secret_probe dialogs | workspace-sign | workspace-inspect | workspace-plugins"
            );
            std::process::exit(2);
        }
    }
}
