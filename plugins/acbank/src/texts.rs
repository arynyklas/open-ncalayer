//! The texts of the signing window, in the page's `settings.locale`.

/// One language's texts.
pub(crate) struct Texts {
    /// The window's title.
    pub title: &'static str,
    /// Above the list of documents.
    pub documents: &'static str,
    /// «Sign», «View», «Cancel».
    pub main_buttons: [&'static str; 3],
    /// The title of the document preview.
    pub preview_title: &'static str,
    /// «View», «Back» of the list of documents to view.
    pub preview_buttons: [&'static str; 2],
    /// Above a document's contents.
    pub content: &'static str,
    /// Above a document's contents that are not JSON.
    pub content_invalid: &'static str,
}

impl Texts {
    pub(crate) const RU: Texts = Texts {
        title: "Подписание данных ЭЦП (Модуль)",
        documents: "Документы для подписи:",
        main_buttons: ["Подписать", "Посмотреть", "Отмена"],
        preview_title: "Просмотр данных",
        preview_buttons: ["Посмотреть", "Назад"],
        content: "Содержимое документа",
        content_invalid: "Содержимое документа (невалидный JSON?)",
    };

    // Unverified against the original: apart from the window's title, the Kazakh and
    // English texts of its dictionary are not known; these are translations.
    pub(crate) const KK: Texts = Texts {
        title: "ЭЦҚ арқылы деректерге қол қою модулі",
        documents: "Қол қоюға арналған құжаттар:",
        main_buttons: ["Қол қою", "Қарау", "Болдырмау"],
        preview_title: "Деректерді қарау",
        preview_buttons: ["Қарау", "Артқа"],
        content: "Құжаттың мазмұны",
        content_invalid: "Құжаттың мазмұны (JSON жарамсыз ба?)",
    };

    pub(crate) const EN: Texts = Texts {
        title: "Data Signing with Digital Signature (Module)",
        documents: "Documents to sign:",
        main_buttons: ["Sign", "View", "Cancel"],
        preview_title: "Data preview",
        preview_buttons: ["View", "Back"],
        content: "Document contents",
        content_invalid: "Document contents (invalid JSON?)",
    };
}
