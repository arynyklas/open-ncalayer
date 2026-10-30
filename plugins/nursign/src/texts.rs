//! The texts of NURSign's errors, as its resource files have them (typos included): English
//! windows get the English file, every other language the Russian one.

use oncl_pdk::Locale;

/// An error of NURSign with a text of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    Cancel,
    MaxFileSizeExceeded,
    UploadFileException,
    CheckFileExistError,
    Other,
    SignPlainDataFailed,
    NotValidUrl,
    FileNotFound,
    DownloadFileException,
    TimestampCreationFailure,
}

impl Code {
    /// The text of the error in `locale`.
    pub fn text(self, locale: Locale) -> &'static str {
        let en = locale == Locale::En;
        match self {
            Code::Cancel if en => "Canceled",
            Code::Cancel => "Отменено",
            Code::MaxFileSizeExceeded => "Превышен максимальный размер файла",
            Code::UploadFileException if en => "Failed to download file",
            Code::UploadFileException => "Не удалось скачать файл",
            Code::CheckFileExistError if en => "Download file not available",
            Code::CheckFileExistError => "Скачиваемый файл не доступен",
            Code::Other if en => "Other error",
            Code::Other => "Неизвестная ошибка",
            Code::SignPlainDataFailed => "Ошибка при формировании ЭЦП",
            Code::NotValidUrl => "Недопустимый адрес URL",
            Code::FileNotFound => "Файл не нейден",
            Code::DownloadFileException if en => "File download error",
            Code::DownloadFileException => "Ошибка при скачивании файла",
            Code::TimestampCreationFailure if en => "Error on create Timestamp",
            Code::TimestampCreationFailure => "Ошибка при формирвоании метки времени",
        }
    }
}
