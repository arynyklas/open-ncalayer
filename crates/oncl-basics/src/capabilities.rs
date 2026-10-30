//! What a plugin may do, said the same way by the install window and the project site:
//! [`CapabilityLine`] is one line, [`capability_text`] its words in a [`Locale`].

use crate::Locale;

/// What a plugin may do, a line each.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CapabilityLine {
    /// Choose the user's key and sign with it.
    Keys,
    /// Show windows.
    Dialogs,
    /// Open and save files the user chooses.
    Files,
    /// Reach these URL prefixes.
    Http(Vec<String>),
    /// Reach the sites of these origins themselves (the page's own site).
    Origins(Vec<String>),
    /// Reach these plain-HTTP prefixes: an unprotected connection.
    HttpInsecure(Vec<String>),
    /// Open key store files the sites name, each once you allow it.
    KeyFiles,
    /// Read files and write into folders the sites name, each once you allow it; written
    /// files of these extensions.
    PageFiles(Vec<String>),
    /// Keep its settings on this computer.
    Settings,
    /// Share data between sites.
    Shared,
}

/// What `capability` lets a plugin do, in `l`.
pub fn capability_text(capability: &CapabilityLine, l: Locale) -> String {
    let t = Texts::of(l);
    match capability {
        CapabilityLine::Keys => t.keys.to_owned(),
        CapabilityLine::Dialogs => t.dialogs.to_owned(),
        CapabilityLine::Files => t.files.to_owned(),
        CapabilityLine::Http(prefixes) => t.http.replace("{0}", &prefixes.join(", ")),
        CapabilityLine::Origins(origins) => t.origins.replace("{0}", &origins.join(", ")),
        CapabilityLine::HttpInsecure(prefixes) => {
            t.http_insecure.replace("{0}", &prefixes.join(", "))
        }
        CapabilityLine::KeyFiles => t.key_files.to_owned(),
        CapabilityLine::PageFiles(extensions) if extensions.is_empty() => {
            t.page_files_read.to_owned()
        }
        CapabilityLine::PageFiles(extensions) => t.page_files.replace(
            "{0}",
            &extensions
                .iter()
                .map(|e| format!(".{e}"))
                .collect::<Vec<_>>()
                .join(", "),
        ),
        CapabilityLine::Settings => t.settings.to_owned(),
        CapabilityLine::Shared => t.shared.to_owned(),
    }
}

/// The capability texts, in one language.
struct Texts {
    keys: &'static str,
    dialogs: &'static str,
    files: &'static str,
    /// `{0}`: the URL prefixes.
    http: &'static str,
    /// `{0}`: the origin patterns.
    origins: &'static str,
    /// `{0}`: the plain-HTTP prefixes.
    http_insecure: &'static str,
    key_files: &'static str,
    page_files_read: &'static str,
    /// `{0}`: the extensions written.
    page_files: &'static str,
    settings: &'static str,
    shared: &'static str,
}

impl Texts {
    fn of(l: Locale) -> &'static Texts {
        match l {
            Locale::Kk => &Texts {
                keys: "кілтіңізді таңдау және онымен қол қою",
                dialogs: "терезелерді көрсету",
                files: "өзіңіз таңдаған файлдарды ашу және сақтау",
                http: "мына мекенжайларға жүгіну: {0}",
                origins: "мына сайттардың өздеріне жүгіну: {0}",
                http_insecure: "қорғалмаған байланыс арқылы жүгіну: {0}",
                key_files: "сайттар атаған кілт файлдарын ашу, әрқайсысын сіз рұқсат еткеннен кейін",
                page_files_read: "сайттар атаған файлдарды оқу, әрқайсысын сіз рұқсат еткеннен кейін",
                page_files: "сайттар атаған файлдарды оқу және папкаларға {0} файлдарын жазу, әрқайсысын сіз рұқсат еткеннен кейін",
                settings: "баптауларын осы компьютерде сақтау",
                shared: "деректерді сайттар арасында бөлісу",
            },
            Locale::Ru => &Texts {
                keys: "выбирать ваш ключ и подписывать им",
                dialogs: "показывать окна",
                files: "открывать и сохранять файлы, которые вы выберете",
                http: "обращаться к {0}",
                origins: "обращаться к самим сайтам {0}",
                http_insecure: "обращаться по незащищённому соединению к {0}",
                key_files: "открывать файлы ключей, которые назовут сайты, — каждый после вашего разрешения",
                page_files_read: "читать файлы, которые назовут сайты, — каждый после вашего разрешения",
                page_files: "читать файлы и записывать файлы {0} в папки, которые назовут сайты, — каждый файл и каждую папку после вашего разрешения",
                settings: "хранить свои настройки на этом компьютере",
                shared: "делить данные между сайтами",
            },
            Locale::En => &Texts {
                keys: "choose your key and sign with it",
                dialogs: "show windows",
                files: "open and save files you choose",
                http: "reach {0}",
                origins: "reach the sites {0} themselves",
                http_insecure: "reach {0} over an unprotected connection",
                key_files: "open key files the sites name, each once you allow it",
                page_files_read: "read files the sites name, each once you allow it",
                page_files: "read files and write {0} files into folders the sites name, each once you allow it",
                settings: "keep its settings on this computer",
                shared: "share data between sites",
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_files_say_when_permission_is_asked() {
        let page_files = CapabilityLine::PageFiles(vec!["xml".to_owned(), "pdf".to_owned()]);
        assert_eq!(
            capability_text(&page_files, Locale::Ru),
            "читать файлы и записывать файлы .xml, .pdf в папки, которые назовут сайты, — \
             каждый файл и каждую папку после вашего разрешения"
        );
        assert_eq!(
            capability_text(&page_files, Locale::En),
            "read files and write .xml, .pdf files into folders the sites name, each once you \
             allow it"
        );
    }

    #[test]
    fn capability_texts_exist_in_every_locale() {
        let list = || vec!["X1".to_owned()];
        let every = [
            CapabilityLine::Keys,
            CapabilityLine::Dialogs,
            CapabilityLine::Files,
            CapabilityLine::Http(list()),
            CapabilityLine::Origins(list()),
            CapabilityLine::HttpInsecure(list()),
            CapabilityLine::KeyFiles,
            CapabilityLine::PageFiles(Vec::new()),
            CapabilityLine::PageFiles(list()),
            CapabilityLine::Settings,
            CapabilityLine::Shared,
        ];
        for l in [Locale::Ru, Locale::Kk, Locale::En] {
            for c in &every {
                let text = capability_text(c, l);
                assert!(!text.trim().is_empty(), "{c:?} {l:?}");
                assert!(!text.contains("{0}"), "{c:?} {l:?}: {text}");
                if matches!(
                    c,
                    CapabilityLine::Http(_)
                        | CapabilityLine::Origins(_)
                        | CapabilityLine::HttpInsecure(_)
                        | CapabilityLine::PageFiles(_)
                ) && c != &CapabilityLine::PageFiles(Vec::new())
                {
                    assert!(text.contains("X1"), "{c:?} {l:?}: {text}");
                }
            }
        }
    }
}
