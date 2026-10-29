//! A driver per token family: the APDUs that open the token, verify the PIN, list the keys
//! with their public keys and certificates, and sign.

/// Holder data of an ID card, read without the PIN.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdCardInfo {
    /// Individual identification number (12 digits).
    pub iin: String,
    /// Last name.
    pub last_name: String,
    /// First name.
    pub first_name: String,
    /// Middle name, when the holder has one.
    pub middle_name: Option<String>,
}

impl IdCardInfo {
    /// `"Last First Middle"`, or `"Last First"` without a middle name.
    pub fn full_name(&self) -> String {
        match &self.middle_name {
            Some(middle) => format!("{} {} {middle}", self.last_name, self.first_name),
            None => format!("{} {}", self.last_name, self.first_name),
        }
    }
}
