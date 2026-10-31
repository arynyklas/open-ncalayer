//! A token PIN that comes from the page (or from a plugin on its behalf) rather than from
//! our own PIN field: it reaches the card only with the user's consent, so that a page can
//! never spend the token's tries, let alone block it, without the user clicking.
//!
//! - The user allows a page's PINs once per origin and reader ([`PagePins`] lives as long
//!   as the session, or the plugin instance serving it); the question names the site and
//!   the token, with the tries left when the token tells them.
//! - With [`ASK_EVERY_TIME_AT`] tries or fewer left, every such PIN is asked about.
//! - A wrong PIN withdraws the consent for that reader: the next PIN needs a new one.
//! - A PIN the user typed in our dialog is sent as it is, but once the card refused it,
//!   sending it again is a page's retry and needs the consent too.
//! - Nothing retries on its own: one call, at most one PIN sent.
//! - Declined: nothing is sent to the card.

use crate::prompt::Locale;
use oncl_pki::pkcs12::KeyEntry;
use oncl_token::drivers::check_pin;
use oncl_token::{TokenError, TokenKind, Tokens};
use std::collections::HashSet;

/// Tries left at or below which every PIN of a page is asked about.
pub const ASK_EVERY_TIME_AT: u8 = 2;

/// Where a PIN sent to a token comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinFrom {
    /// The page, or a plugin on its behalf.
    Page,
    /// The user, in our password dialog: the id under which the dialog's answer is kept.
    Typed(u32),
}

/// A PIN about to be sent: for a page of `origin`, to the token of `kind` in `reader`. Not
/// `Debug`: it carries the PIN.
#[derive(Clone, Copy)]
pub struct PinUse<'a> {
    /// The page's origin, as the question shows it.
    pub origin: &'a str,
    /// The reader.
    pub reader: &'a str,
    /// The token family.
    pub kind: TokenKind,
    /// The PIN.
    pub pin: &'a str,
    /// Where the PIN comes from.
    pub from: PinFrom,
}

/// Why [`PagePins::open`] opened nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinRefusal {
    /// The user did not allow it: nothing was sent to the card.
    Declined,
    /// The token's error.
    Token(TokenError),
}

/// What the user allowed in a session: the (origin, reader) pairs whose page PINs may be
/// sent, and the typed PINs the card refused.
#[derive(Debug, Default)]
pub struct PagePins {
    allowed: HashSet<(String, String)>,
    refused_typed: HashSet<u32>,
}

impl PagePins {
    /// Opens the token as [`Tokens::open`] with the PIN of `pin_use`, asking `ask` first
    /// when the PIN needs the user's consent. `ask` gets the tries left (when the token
    /// tells them) and answers whether the user allowed it.
    ///
    /// # Errors
    ///
    /// [`PinRefusal::Declined`] when the user did not allow it; [`PinRefusal::Token`] with
    /// [`TokenError::PinBlocked`] for a token without tries left (no PIN sent), and the
    /// errors of [`Tokens::pin_tries`] and [`Tokens::open`].
    pub fn open(
        &mut self,
        tokens: &Tokens,
        pin_use: PinUse<'_>,
        ask: impl FnOnce(Option<u8>) -> bool,
    ) -> Result<Vec<KeyEntry>, PinRefusal> {
        let PinUse {
            origin,
            reader,
            kind,
            pin,
            from,
        } = pin_use;
        if !tokens.is_enabled() {
            return Err(PinRefusal::Token(TokenError::Disabled));
        }
        // A PIN the card cannot take goes nowhere: no try, no question.
        check_pin(kind, pin).map_err(PinRefusal::Token)?;
        let guarded = match from {
            PinFrom::Page => true,
            PinFrom::Typed(id) => self.refused_typed.contains(&id),
        };
        if guarded {
            let tries = tokens.pin_tries(reader, kind).map_err(PinRefusal::Token)?;
            if tries == Some(0) {
                return Err(PinRefusal::Token(TokenError::PinBlocked));
            }
            let key = (origin.to_owned(), reader.to_owned());
            let few = tries.is_some_and(|n| n <= ASK_EVERY_TIME_AT);
            if few || !self.allowed.contains(&key) {
                if !ask(tries) {
                    return Err(PinRefusal::Declined);
                }
                self.allowed.insert(key);
            }
        }
        tokens.open(reader, kind, pin).map_err(|e| {
            if matches!(e, TokenError::WrongPin { .. } | TokenError::PinBlocked) {
                self.allowed.retain(|(_, r)| r != reader);
                if let PinFrom::Typed(id) = from {
                    self.refused_typed.insert(id);
                }
            }
            PinRefusal::Token(e)
        })
    }
}

/// The question that lets a page send a PIN to the token of `kind` in `reader`, through
/// `source` (a plugin's name), with the tries left when the token tells them.
pub fn page_pin_text(
    locale: Locale,
    origin: &str,
    source: &str,
    kind: TokenKind,
    reader: &str,
    tries: Option<u8>,
) -> String {
    let token = token_name(kind, locale);
    let tries = tries.map_or_else(String::new, |n| match locale {
        Locale::Ru => format!("\nОсталось попыток: {n}."),
        Locale::Kk => format!("\nҚалған әрекет саны: {n}."),
        Locale::En => format!("\nTries left: {n}."),
    });
    match locale {
        Locale::Ru => format!(
            "Сайт {origin} через плагин «{plugin}» просит проверить свой PIN-код на носителе {token} в считывателе «{reader}».{tries}\n\nНеверный PIN-код отнимает попытку, а когда попытки кончатся, носитель заблокируется.\n\nРазрешить?",
            plugin = source
        ),
        Locale::Kk => format!(
            "{origin} сайты «{plugin}» плагині арқылы «{reader}» оқу құрылғысындағы {token} тасымалдағышында өз PIN-кодын тексеруді сұрайды.{tries}\n\nҚате PIN-код бір әрекетті алады, ал әрекеттер таусылғанда тасымалдағыш бұғатталады.\n\nРұқсат етесіз бе?",
            plugin = source
        ),
        Locale::En => format!(
            "The site {origin} asks, through the plugin “{plugin}”, to check its own PIN on the {token} in the reader “{reader}”.{tries}\n\nA wrong PIN uses up a try, and when none are left the token is blocked.\n\nAllow?",
            plugin = source
        ),
    }
}

/// The token's name as the storage dialog shows it.
fn token_name(kind: TokenKind, locale: Locale) -> &'static str {
    match kind {
        TokenKind::Kaztoken => "Kaztoken",
        TokenKind::KzIdCard => match locale {
            Locale::Ru => "удостоверение личности",
            Locale::Kk => "жеке куәлік",
            Locale::En => "ID card",
        },
        TokenKind::EToken72K => "eToken 72K",
        TokenKind::EToken5110 => "eToken 5110",
        TokenKind::JaCarta => "JaCarta",
        TokenKind::AKey => "aKey",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_names_site_plugin_token_reader_and_tries() {
        let text = page_pin_text(
            Locale::Ru,
            "https://x.kz",
            "Плагин",
            TokenKind::Kaztoken,
            "Reader 0",
            Some(3),
        );
        for part in [
            "https://x.kz",
            "«Плагин»",
            "Kaztoken",
            "«Reader 0»",
            "Осталось попыток: 3.",
        ] {
            assert!(text.contains(part), "{part}: {text}");
        }
        for locale in [Locale::Kk, Locale::En] {
            let text = page_pin_text(locale, "o", "p", TokenKind::KzIdCard, "r", Some(7));
            assert!(text.contains(": 7."), "{text}");
        }
        let unknown = page_pin_text(Locale::En, "o", "p", TokenKind::JaCarta, "r", None);
        assert!(!unknown.contains("Tries left"), "{unknown}");
    }
}
