//! The replies of the ecc.kz family (MarketSign, EFactoringSign, NURSign, K2Sign): an
//! org.json `new JSONObject()`, so the keys come out in Java's `HashMap` order.

use oncl_pdk::orgjson::{JObject, JValue};

/// `{"result":…,"errorCode":…}`: `result` put first, then `errorCode`; a `None` leaves its
/// key out (`{"errorCode":"CANCEL"}`, eFactoring's `{"result":…}`, NURSign's `{}`).
pub fn ecc(result: Option<JValue>, error_code: Option<&str>) -> String {
    let mut reply = JObject::hash_map();
    reply.put_opt("result", result);
    reply.put_opt("errorCode", error_code);
    reply.to_json()
}

/// `{"errorMessage":…,"errorCode":…}`: `errorCode` put first, then `errorMessage`, as the
/// originals did; the `HashMap` writes `errorMessage` first.
pub fn error_text(message: &str, error_code: &str) -> String {
    let mut reply = JObject::hash_map();
    reply.put("errorCode", error_code);
    reply.put("errorMessage", message);
    reply.to_json()
}

#[cfg(test)]
mod tests {
    use super::{ecc, error_text};
    use oncl_pdk::orgjson::{JObject, JValue};

    #[test]
    fn ecc_result_and_code() {
        let mut version = JObject::hash_map();
        version.put("version", "1.0.0");
        assert_eq!(
            ecc(Some(JValue::Obj(version)), Some("NONE")),
            r#"{"result":{"version":"1.0.0"},"errorCode":"NONE"}"#
        );
        assert_eq!(
            ecc(Some("<a>x</a>".into()), Some("NONE")),
            r#"{"result":"<a>x<\/a>","errorCode":"NONE"}"#
        );
    }

    #[test]
    fn ecc_leaves_out_none() {
        assert_eq!(ecc(None, Some("CANCEL")), r#"{"errorCode":"CANCEL"}"#);
        assert_eq!(ecc(Some("MIIB".into()), None), r#"{"result":"MIIB"}"#);
        assert_eq!(ecc(None, None), "{}");
    }

    #[test]
    fn error_text_in_hash_map_order() {
        assert_eq!(
            error_text(" Неизвестный тип ", "UNKNOWN TYPE"),
            r#"{"errorMessage":" Неизвестный тип ","errorCode":"UNKNOWN TYPE"}"#
        );
        assert_eq!(
            error_text("a\nb", "500"),
            r#"{"errorMessage":"a\nb","errorCode":"500"}"#
        );
    }
}
