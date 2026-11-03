use serde::{Deserialize, Serialize};

/// Raw request bytes are streamed, not deserialized into a document allocation.
/// Algorithm and operation are fixed by this implemented route (SHA-256/hash).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HashResponse {
    pub operation_id: u64,
    pub algorithm: String,
    pub digest: String,
    pub bytes_in: u64,
}
