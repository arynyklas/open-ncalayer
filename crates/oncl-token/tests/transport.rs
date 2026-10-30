//! APDU encoding, the T=0 transport rules (GET RESPONSE chains, wrong-length resends, case 4
//! as case 3), the limits against a hostile card, the redacted trace, and the ATR table.

use hex_literal::hex;
use oncl_token::apdu::{Command, Response};
use oncl_token::backend::{BackendError, Connection, Protocol};
use oncl_token::card::Card;
use oncl_token::{ATRS, MAX_GET_RESPONSE, TokenError, TokenKind};
use std::collections::VecDeque;
use std::io::Write;
use std::sync::{Arc, Mutex};

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// A connection that expects exactly the scripted commands, in order.
struct ScriptedConnection {
    protocol: Protocol,
    script: VecDeque<(Vec<u8>, Vec<u8>)>,
}

impl ScriptedConnection {
    fn new(protocol: Protocol, script: &[(&[u8], &[u8])]) -> ScriptedConnection {
        ScriptedConnection {
            protocol,
            script: script
                .iter()
                .map(|(c, r)| (c.to_vec(), r.to_vec()))
                .collect(),
        }
    }
}

impl Connection for ScriptedConnection {
    fn protocol(&self) -> Protocol {
        self.protocol
    }

    fn atr(&self) -> &[u8] {
        &[]
    }

    fn begin_transaction(&mut self) -> Result<(), BackendError> {
        Ok(())
    }

    fn end_transaction(&mut self) -> Result<(), BackendError> {
        Ok(())
    }

    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, BackendError> {
        let (expected, response) = self
            .script
            .pop_front()
            .unwrap_or_else(|| panic!("unexpected command {}", hex_of(apdu)));
        assert_eq!(
            hex_of(apdu),
            hex_of(&expected),
            "command {} where {} was expected",
            hex_of(apdu),
            hex_of(&expected)
        );
        Ok(response)
    }

    fn reset_on_disconnect(&mut self) {}
}

impl Drop for ScriptedConnection {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            assert!(
                self.script.is_empty(),
                "commands not sent: {:?}",
                self.script
                    .iter()
                    .map(|(c, _)| hex_of(c))
                    .collect::<Vec<_>>()
            );
        }
    }
}

#[test]
fn encode_cases_short_and_extended() {
    let data258: Vec<u8> = (0..258u32).map(|i| i as u8).collect();
    let cases: Vec<(Command, Vec<u8>)> = vec![
        (
            Command::new(0x80, 0x40, 0x00, 0x00),
            hex!("80400000").to_vec(),
        ),
        (
            Command::new(0x00, 0xB0, 0x00, 0x00).with_le(256),
            hex!("00B0000000").to_vec(),
        ),
        (
            Command::new(0x00, 0xB0, 0x01, 0x02).with_le(0xFF),
            hex!("00B00102FF").to_vec(),
        ),
        (
            Command::new(0x00, 0x20, 0x00, 0x02).with_data(b"1234".to_vec()),
            hex!("002000020431323334").to_vec(),
        ),
        (
            Command::new(0x00, 0x2A, 0x9E, 0x9A)
                .with_data(vec![0xAA; 2])
                .with_le(0xFF),
            hex!("002A9E9A02AAAAFF").to_vec(),
        ),
        (
            Command::new(0x80, 0x14, 0x23, 0x24).with_data(data258.clone()),
            [&hex!("80142324000102")[..], &data258].concat(),
        ),
        (
            Command::new(0x80, 0x14, 0x23, 0x24)
                .with_data(vec![1, 2])
                .with_le(258),
            hex!("8014232400000201020102").to_vec(),
        ),
        (
            Command::new(0x80, 0x12, 0x28, 0x00).with_le(65536),
            hex!("80122800000000").to_vec(),
        ),
        (
            Command::new(0x80, 0x12, 0x28, 0x00).with_le(4096),
            hex!("80122800001000").to_vec(),
        ),
    ];
    for (cmd, expected) in cases {
        assert_eq!(hex_of(&cmd.encode()), hex_of(&expected));
    }
    assert!(!Command::new(0, 0, 0, 0).with_le(256).is_extended());
    assert!(Command::new(0, 0, 0, 0).with_le(257).is_extended());
    assert!(
        Command::new(0, 0, 0, 0)
            .with_data(vec![0; 256])
            .is_extended()
    );
}

#[test]
fn response_parse() {
    assert_eq!(
        Response::parse(&hex!("01029000")).unwrap(),
        Response {
            data: vec![1, 2],
            sw: 0x9000
        }
    );
    let r = Response::parse(&hex!("63C3")).unwrap();
    assert_eq!((r.sw1(), r.sw2(), r.is_ok()), (0x63, 0xC3, false));
    assert!(matches!(
        Response::parse(&[0x90]),
        Err(TokenError::Transport(_))
    ));
}

#[test]
fn get_response_chain_is_followed() {
    let mut conn = ScriptedConnection::new(
        Protocol::T0,
        &[
            (&hex!("00CA0181FF"), &hex!("0102 6110")),
            (
                &hex!("00C0000010"),
                &[&[3u8; 16][..], &hex!("6100")].concat(),
            ),
            (&hex!("00C0000000"), &hex!("04 9000")),
        ],
    );
    let mut card = Card::new(&mut conn, false);
    let r = card
        .transmit(&Command::new(0x00, 0xCA, 0x01, 0x81).with_le(0xFF))
        .unwrap();
    assert_eq!(r.sw, 0x9000);
    let mut expected = vec![1, 2];
    expected.extend([3; 16]);
    expected.push(4);
    assert_eq!(r.data, expected);
}

#[test]
fn wrong_length_is_resent_once() {
    let mut conn = ScriptedConnection::new(
        Protocol::T0,
        &[
            (&hex!("00CA0181FF"), &hex!("6C08")),
            (&hex!("00CA018108"), &hex!("6C04")),
        ],
    );
    let mut card = Card::new(&mut conn, false);
    let r = card
        .transmit(&Command::new(0x00, 0xCA, 0x01, 0x81).with_le(0xFF))
        .unwrap();
    assert_eq!(r.sw, 0x6C04);
}

#[test]
fn t0_case4_sent_as_case3() {
    let mut conn = ScriptedConnection::new(
        Protocol::T0,
        &[
            (&hex!("002A9E9A0211 22"), &hex!("6102")),
            (&hex!("00C0000002"), &hex!("AABB9000")),
        ],
    );
    let mut card = Card::new(&mut conn, false);
    let cmd = Command::new(0x00, 0x2A, 0x9E, 0x9A)
        .with_data(vec![0x11, 0x22])
        .with_le(0xFF);
    assert_eq!(card.expect(&cmd, "sign").unwrap(), hex!("AABB"));

    // Under T=1 the same command keeps its Le.
    let mut conn = ScriptedConnection::new(
        Protocol::T1,
        &[(&hex!("002A9E9A021122FF"), &hex!("AABB9000"))],
    );
    let mut card = Card::new(&mut conn, false);
    assert_eq!(card.expect(&cmd, "sign").unwrap(), hex!("AABB"));
}

#[test]
fn extended_over_t0_is_refused() {
    let mut conn = ScriptedConnection::new(Protocol::T0, &[]);
    let mut card = Card::new(&mut conn, false);
    let cmd = Command::new(0x80, 0x14, 0x23, 0x24).with_data(vec![0; 300]);
    assert_eq!(
        card.transmit(&cmd),
        Err(TokenError::Transport("extended APDU over T=0".to_owned()))
    );
}

#[test]
fn endless_61xx_is_cut() {
    let mut script: Vec<(&[u8], &[u8])> = vec![(&hex!("80150000"), &hex!("61FF"))];
    for _ in 0..MAX_GET_RESPONSE {
        script.push((&hex!("00C00000FF"), &hex!("61FF")));
    }
    let mut conn = ScriptedConnection::new(Protocol::T0, &script);
    let mut card = Card::new(&mut conn, false);
    assert!(matches!(
        card.transmit(&Command::new(0x80, 0x15, 0x00, 0x00)),
        Err(TokenError::Transport(_))
    ));
}

#[test]
fn oversized_response_is_cut() {
    // A hostile card that answers more than asked: 66 answers of 1000 bytes pass the 65 538
    // bytes allowed long before the GET RESPONSE limit.
    let big = [&[0u8; 1000][..], &hex!("61FF")].concat();
    let mut script: Vec<(&[u8], &[u8])> = vec![(&hex!("80150000"), &big)];
    for _ in 0..65 {
        script.push((&hex!("00C00000FF"), &big));
    }
    let mut conn = ScriptedConnection::new(Protocol::T0, &script);
    let mut card = Card::new(&mut conn, false);
    assert!(matches!(
        card.transmit(&Command::new(0x80, 0x15, 0x00, 0x00)),
        Err(TokenError::Transport(_))
    ));
}

#[test]
fn card_errors_carry_the_status_word() {
    let mut conn = ScriptedConnection::new(Protocol::T1, &[(&hex!("80400000"), &hex!("6D00"))]);
    let mut card = Card::new(&mut conn, false);
    assert_eq!(
        card.expect(&Command::new(0x80, 0x40, 0, 0), "logout"),
        Err(TokenError::Card {
            op: "logout",
            sw: 0x6D00
        })
    );
}

#[test]
fn read_binary_chunks_by_255() {
    let chunk = |n: usize, b: u8| [vec![b; n], hex!("9000").to_vec()].concat();
    let (a, b, c) = (chunk(255, 1), chunk(255, 2), chunk(90, 3));
    let mut conn = ScriptedConnection::new(
        Protocol::T1,
        &[
            (&hex!("00B00000FF"), &a),
            (&hex!("00B000FFFF"), &b),
            (&hex!("00B001FE5A"), &c),
        ],
    );
    let mut card = Card::new(&mut conn, false);
    let data = card.read_binary(0, 600).unwrap();
    assert_eq!(data.len(), 600);
    assert_eq!((data[0], data[255], data[599]), (1, 2, 3));
}

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn pin_is_redacted_in_trace() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let mut conn = ScriptedConnection::new(
            Protocol::T1,
            &[
                (&hex!("002000020431323334"), &hex!("9000")),
                (&hex!("00CA0181FF"), &hex!("A1B29000")),
            ],
        );
        let mut card = Card::new(&mut conn, true);
        let verify = Command::new(0x00, 0x20, 0x00, 0x02)
            .with_data(b"1234".to_vec())
            .redacted();
        card.expect(&verify, "verify").unwrap();
        card.expect(
            &Command::new(0x00, 0xCA, 0x01, 0x81).with_le(0xFF),
            "get data",
        )
        .unwrap();
    });
    let text = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(text.contains("<redacted 4 bytes>"), "{text}");
    assert!(!text.contains("31 32 33 34"), "{text}");
    assert!(!text.contains("31323334"), "{text}");
    assert!(text.contains("00 CA 01 81"), "{text}");
}

#[test]
fn trace_is_off_without_the_flag() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let mut conn = ScriptedConnection::new(Protocol::T1, &[(&hex!("80400000"), &hex!("9000"))]);
        let mut card = Card::new(&mut conn, false);
        card.expect(&Command::new(0x80, 0x40, 0, 0), "logout")
            .unwrap();
    });
    assert!(captured.0.lock().unwrap().is_empty());
}

#[test]
fn atr_table_maps_exactly() {
    assert_eq!(ATRS.len(), 18);
    for (kind, atr) in ATRS {
        assert_eq!(TokenKind::from_atr(atr), Some(*kind), "{}", hex_of(atr));
        let mut longer = atr.to_vec();
        longer.push(0);
        assert_eq!(TokenKind::from_atr(&longer), None);
        assert_eq!(TokenKind::from_atr(&atr[..atr.len() - 1]), None);
    }
    for kind in TokenKind::ALL {
        assert!(ATRS.iter().any(|(k, _)| *k == kind), "{kind:?} has an ATR");
    }
    assert_eq!(
        TokenKind::from_atr(&hex!("3B88014B415A544F4B454E82")),
        Some(TokenKind::Kaztoken)
    );
}

#[test]
fn storage_names_roundtrip() {
    let names: Vec<&str> = TokenKind::ALL.iter().map(|k| k.storage_name()).collect();
    assert_eq!(
        names,
        [
            "AKKaztokenStore",
            "AKKZIDCardStore",
            "AKEToken72KStore",
            "AKEToken5110Store",
            "AKJaCartaStore",
            "AKAKEYStore",
        ]
    );
    for kind in TokenKind::ALL {
        assert_eq!(
            TokenKind::from_storage_name(kind.storage_name()),
            Some(kind)
        );
    }
    assert_eq!(TokenKind::from_storage_name("akkaztokenstore"), None);
    assert_eq!(TokenKind::from_storage_name("PKCS12"), None);
    let tries: Vec<TokenKind> = TokenKind::ALL
        .into_iter()
        .filter(|k| k.reports_tries())
        .collect();
    assert_eq!(
        tries,
        [TokenKind::Kaztoken, TokenKind::KzIdCard, TokenKind::AKey]
    );
}

#[test]
fn backend_errors_map_to_token_errors() {
    for (backend, token) in [
        (BackendError::NoService, TokenError::NoService),
        (BackendError::NoReaders, TokenError::NoDevice),
        (BackendError::UnknownReader, TokenError::NoDevice),
        (BackendError::NoCard, TokenError::NoDevice),
        (BackendError::Removed, TokenError::CardRemoved),
        (BackendError::Reset, TokenError::CardRemoved),
    ] {
        assert_eq!(TokenError::from(backend), token);
    }
    assert!(matches!(
        TokenError::from(BackendError::Sharing),
        TokenError::Transport(_)
    ));
    assert!(matches!(
        TokenError::from(BackendError::Failed("x".into())),
        TokenError::Transport(_)
    ));
}
