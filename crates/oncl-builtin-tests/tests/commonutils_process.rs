//! `kz.gov.pki.knca.commonUtils` across sessions: its dialog language belongs to the
//! process, and the windows of two calls never interleave.

use oncl_builtin_tests::commonutils::{CommonUtils, MODULE_NAME};
use oncl_flows::testing::{ScriptedPrompter, Step};
use oncl_flows::{Locale, StoragePrompt};
use oncl_pki::http::{HttpError, HttpReply, HttpRequest, HttpTransport};
use oncl_protocol::{AddInfo, Module};
use serde_json::{Value, json};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

/// No network: nothing here signs.
struct Offline;

impl HttpTransport for Offline {
    fn send(&self, _: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        Err(HttpError::other("offline"))
    }
}

fn session(id: u64) -> AddInfo {
    AddInfo {
        origin: Some(format!("https://page{id}.kz")),
        session: id,
    }
}

fn call(cu: &CommonUtils, method: &str, args: Value, add_info: &AddInfo) -> Value {
    let request = json!({"module": MODULE_NAME, "method": method, "args": args}).to_string();
    serde_json::from_str(cu.process(&request, add_info).text().unwrap()).unwrap()
}

fn locales(prompts: &[StoragePrompt]) -> Vec<Locale> {
    prompts.iter().map(|p| p.locale).collect()
}

#[test]
fn locale_is_process_wide() {
    let prompter = Arc::new(ScriptedPrompter::new(vec![
        Step::CancelStorage,
        Step::CancelStorage,
        Step::CancelStorage,
    ]));
    let cu = CommonUtils::new(prompter.clone(), Arc::new(Offline));
    let (one, two) = (session(1), session(2));
    let key_info = |add_info| call(&cu, "getKeyInfo", json!(["PKCS12"]), add_info);
    assert_eq!(key_info(&two)["message"], "action.canceled");
    // One page switches the language: the other page's windows follow.
    assert_eq!(
        call(&cu, "changeLocale", json!(["kk"]), &one),
        json!({"code": "200"})
    );
    assert_eq!(key_info(&two)["message"], "action.canceled");
    call(&cu, "changeLocale", json!(["en"]), &two);
    assert_eq!(key_info(&one)["message"], "action.canceled");
    assert_eq!(
        locales(&prompter.storage_prompts()),
        [Locale::Ru, Locale::Kk, Locale::En]
    );
}

#[test]
fn dialog_turn_spans_the_flow() {
    let opened = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let prompter = Arc::new(ScriptedPrompter::new(vec![
        Step::Wait(Arc::clone(&opened)),
        Step::Wait(Arc::clone(&release)),
        Step::CancelStorage,
        Step::CancelStorage,
    ]));
    let cu = Arc::new(CommonUtils::new(prompter.clone(), Arc::new(Offline)));
    let key_info = |cu: Arc<CommonUtils>, id| {
        thread::spawn(move || call(&cu, "getKeyInfo", json!(["PKCS12"]), &session(id)))
    };
    let first = key_info(Arc::clone(&cu), 1);
    // The first call's storage dialog is up.
    opened.wait();
    let second = key_info(Arc::clone(&cu), 2);
    thread::sleep(Duration::from_millis(300));
    assert_eq!(
        prompter.storage_prompts().len(),
        1,
        "the second call's window waits for the first call's flow"
    );
    release.wait();
    for call in [first, second] {
        assert_eq!(call.join().unwrap()["message"], "action.canceled");
    }
    assert_eq!(prompter.storage_prompts().len(), 2);
}
