use std::fmt;

/// Typed error representation for rustpass operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Password length or word count is invalid (e.g., zero).
    InvalidLength(String),
    /// Character pool is empty based on current inclusion/exclusion settings.
    EmptyPool(String),
    /// Configuration options conflict with each other.
    ConflictingOptions(String),
    /// Wordlist is empty or contains no valid entries.
    InvalidWordlist(String),
    /// Failure during clipboard operations.
    Clipboard(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidLength(msg) => write!(f, "Invalid length: {}", msg),
            Error::EmptyPool(msg) => write!(f, "Empty pool: {}", msg),
            Error::ConflictingOptions(msg) => write!(f, "Conflicting options: {}", msg),
            Error::InvalidWordlist(msg) => write!(f, "Invalid wordlist: {}", msg),
            Error::Clipboard(msg) => write!(f, "Clipboard error: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
