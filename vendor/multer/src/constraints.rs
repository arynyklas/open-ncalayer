use crate::size_limit::SizeLimit;

/// Observe only newly proven raw multipart framing bytes. The callback cannot
/// alter input, parser position or field roles; an error aborts parsing.
pub trait FramingObserver: Send + Sync {
    fn observe(&self, bytes: u64) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// Represents some rules to be applied on the stream and field's content size
/// to prevent DoS attacks.
///
/// It's recommended to add some rules on field (specially text field) size to
/// avoid potential DoS attacks from attackers running the server out of memory.
/// This type provides some API to apply constraints on very granular level to
/// make `multipart/form-data` safe. By default, it does not apply any
/// constraint.
///
/// # Examples
///
/// ```
/// use multer::{Multipart, Constraints, SizeLimit};
/// # use bytes::Bytes;
/// # use std::convert::Infallible;
/// # use futures_util::stream::once;
///
/// # async fn run() {
/// # let data = "--X-BOUNDARY\r\nContent-Disposition: form-data; name=\"my_text_field\"\r\n\r\nabcd\r\n--X-BOUNDARY--\r\n";
/// # let some_stream = once(async move { Result::<Bytes, Infallible>::Ok(Bytes::from(data)) });
/// // Create some constraints to be applied to the fields to prevent DoS attack.
/// let constraints = Constraints::new()
///      // We only accept `my_text_field` and `my_file_field` fields,
///      // For any unknown field, we will throw an error.
///      .allowed_fields(vec!["my_text_field", "my_file_field"])
///      .size_limit(
///          SizeLimit::new()
///              // Set 15mb as size limit for the whole stream body.
///              .whole_stream(15 * 1024 * 1024)
///              // Set 10mb as size limit for all fields.
///              .per_field(10 * 1024 * 1024)
///              // Set 30kb as size limit for our text field only.
///              .for_field("my_text_field", 30 * 1024),
///      );
///
/// // Create a `Multipart` instance from a stream and the constraints.
/// let mut multipart = Multipart::with_constraints(some_stream, "X-BOUNDARY", constraints);
///
/// while let Some(field) = multipart.next_field().await.unwrap() {
///     let content = field.text().await.unwrap();
///     assert_eq!(content, "abcd");
/// }
/// # }
/// # tokio::runtime::Runtime::new().unwrap().block_on(run());
/// ```
#[derive(Default)]
pub struct Constraints {
    pub(crate) size_limit: SizeLimit,
    pub(crate) allowed_fields: Option<Vec<String>>,
    pub(crate) framing_observer: Option<std::sync::Arc<dyn FramingObserver>>,
}

impl std::fmt::Debug for Constraints {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Constraints")
            .field("size_limit", &self.size_limit)
            .field("allowed_fields", &self.allowed_fields)
            .field("framing_observer", &self.framing_observer.is_some())
            .finish()
    }
}

impl Constraints {
    /// Creates a set of rules with default behaviour.
    pub fn new() -> Constraints {
        Constraints::default()
    }

    /// Install a trusted host framing-admission observer. No observer preserves
    /// the upstream parser's ordinary behavior.
    pub fn framing_observer(mut self, observer: std::sync::Arc<dyn FramingObserver>) -> Self {
        self.framing_observer = Some(observer);
        self
    }

    /// Applies rules on field's content length.
    pub fn size_limit(self, size_limit: SizeLimit) -> Constraints {
        Constraints {
            size_limit,
            allowed_fields: self.allowed_fields,
            framing_observer: self.framing_observer,
        }
    }

    /// Specify which fields should be allowed, for any unknown field, the
    /// [`next_field`](crate::Multipart::next_field) will throw an error.
    pub fn allowed_fields<N: Into<String>>(self, allowed_fields: Vec<N>) -> Constraints {
        let allowed_fields = allowed_fields.into_iter().map(|item| item.into()).collect();

        Constraints {
            size_limit: self.size_limit,
            allowed_fields: Some(allowed_fields),
            framing_observer: self.framing_observer,
        }
    }

    pub(crate) fn is_it_allowed(&self, field: Option<&str>) -> bool {
        if let Some(ref allowed_fields) = self.allowed_fields {
            field
                .map(|field| allowed_fields.iter().any(|item| item == field))
                .unwrap_or(false)
        } else {
            true
        }
    }
}
