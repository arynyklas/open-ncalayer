//! The smart card service seen by the drivers: readers, their cards, and connections that
//! exchange APDUs.

/// Transmission protocol of a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    /// T=0: byte-oriented; no extended APDUs, responses through GET RESPONSE.
    T0,
    /// T=1: block-oriented.
    T1,
}

/// A reader and the card in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReaderState {
    /// Reader name.
    pub name: String,
    /// ATR of the card; `None` without a card or when the card does not answer.
    pub atr: Option<Vec<u8>>,
}

/// A smart card service (PC/SC, or the emulator).
pub trait Backend: Send + Sync {
    /// The readers and the ATRs of their cards.
    ///
    /// # Errors
    ///
    /// [`BackendError::NoService`] without the service, [`BackendError::NoReaders`] when
    /// it has no reader, others as the service reports them.
    fn readers(&self) -> Result<Vec<ReaderState>, BackendError>;

    /// Connects to the card in `reader`, shared, T=0 or T=1.
    ///
    /// # Errors
    ///
    /// As the service reports them: [`BackendError::UnknownReader`],
    /// [`BackendError::NoCard`], …
    fn connect(&self, reader: &str) -> Result<Box<dyn Connection>, BackendError>;
}

/// A connection to a card. Dropping it disconnects, leaving the card as it is, or resetting
/// it after [`Connection::reset_on_disconnect`]: the reset ends a PIN verification for
/// everyone, and every other connection to the card then reports [`BackendError::Reset`].
pub trait Connection: Send {
    /// Protocol of the connection.
    fn protocol(&self) -> Protocol;

    /// ATR of the card.
    fn atr(&self) -> &[u8];

    /// Starts exclusive access to the card, waiting for another holder to end its own.
    ///
    /// # Errors
    ///
    /// As the service reports them.
    fn begin_transaction(&mut self) -> Result<(), BackendError>;

    /// Ends exclusive access.
    ///
    /// # Errors
    ///
    /// As the service reports them.
    fn end_transaction(&mut self) -> Result<(), BackendError>;

    /// Sends a command APDU, returns the response bytes (data and status word).
    ///
    /// # Errors
    ///
    /// [`BackendError::Removed`] when the card is gone, others as the service reports them.
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, BackendError>;

    /// The card is reset when the connection is dropped (a PIN was sent to it).
    fn reset_on_disconnect(&mut self);
}

/// Error of the smart card service.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BackendError {
    /// The service (or its library) is not available.
    #[error("the smart card service is not available")]
    NoService,
    /// The service has no reader.
    #[error("no smart card reader")]
    NoReaders,
    /// No reader of that name.
    #[error("unknown smart card reader")]
    UnknownReader,
    /// No card in the reader.
    #[error("no card in the reader")]
    NoCard,
    /// The card was removed.
    #[error("the card was removed")]
    Removed,
    /// The card was reset by another application.
    #[error("the card was reset")]
    Reset,
    /// Another application holds the card exclusively.
    #[error("the card is used by another application")]
    Sharing,
    /// Another failure: the function and its code.
    #[error("smart card service failure: {0}")]
    Failed(String),
}

/// The service when token support is off: there is none.
#[derive(Clone, Copy, Debug, Default)]
pub struct NullBackend;

impl Backend for NullBackend {
    fn readers(&self) -> Result<Vec<ReaderState>, BackendError> {
        Err(BackendError::NoService)
    }

    fn connect(&self, _reader: &str) -> Result<Box<dyn Connection>, BackendError> {
        Err(BackendError::NoService)
    }
}
