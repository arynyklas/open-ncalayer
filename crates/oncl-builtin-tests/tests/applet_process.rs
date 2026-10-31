//! `kz.gov.pki.knca.applet.Applet` across sessions: its PIN try count belongs to the
//! process.

use oncl_builtin_tests::applet::Applet;
use oncl_flows::StorageKind;
use oncl_flows::testing::{ScriptedPrompter, Step};
use oncl_protocol::{AddInfo, Module};
use oncl_testkit::synthetic;
use oncl_token::emulator::{CardSpec, EmuKey, EmulatorBackend, card};
use oncl_token::{TokenKind, Tokens};
use serde_json::{Value, json};
use std::sync::Arc;

const READER: &str = "OpenNCALayer Emulated Reader 0";

fn session(id: u64) -> AddInfo {
    AddInfo {
        origin: Some(format!("https://page{id}.kz")),
        session: id,
    }
}

fn call(a: &Applet, method: &str, args: Value, add_info: &AddInfo) -> Value {
    let request = json!({"method": method, "args": args}).to_string();
    serde_json::from_str(a.process(&request, add_info).text().unwrap()).unwrap()
}

#[test]
fn try_count_is_process_wide() {
    let key = synthetic("user-gost2015-sign");
    let spec = CardSpec::new(
        TokenKind::Kaztoken,
        "123456",
        vec![EmuKey::load(&key.path, &key.password).unwrap()],
    );
    let emu = Arc::new(EmulatorBackend::new());
    emu.add_reader(READER);
    emu.insert(READER, card(spec));
    let prompter = Arc::new(ScriptedPrompter::new(vec![
        Step::Token {
            storage: StorageKind::Token("AKKaztokenStore"),
            reader: READER.to_owned(),
            pin: "000000".to_owned(),
        },
        Step::CancelStorage,
    ]));
    let a = Applet::new(prompter).with_tokens(Tokens::new(emu, true));
    let (one, two) = (session(1), session(2));
    let tries = |add_info| call(&a, "getTryCount", json!([]), add_info);
    assert_eq!(tries(&two), json!({"errorCode": "NONE", "result": -1}));
    // A wrong PIN in one page's call: the other page reads the tries left.
    assert_eq!(
        call(
            &a,
            "signXml",
            json!(["AKKaztokenStore", READER, "SIGN", "<a/>"]),
            &one
        ),
        json!({"errorCode": "SIGN_CANCEL"})
    );
    assert_eq!(tries(&two), json!({"errorCode": "NONE", "result": 9}));
    assert_eq!(tries(&one), json!({"errorCode": "NONE", "result": 9}));
}
