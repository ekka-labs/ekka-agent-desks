//! One error type for the whole tool. Every failure carries a reason a person can act on, and a kind that decides
//! the exit status. No reason ever holds a secret: callers name files, hashes and settings, never key material.

use std::fmt;

/// How a command ended when it did not succeed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The command line was wrong. Exit 2.
    Usage,
    /// Refused before any change, for example a foreign organization. Exit 3.
    Refused,
    /// Something failed part way; what was done is named. Exit 1.
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub kind: Kind,
    pub reason: String,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn exit_code(&self) -> u8 {
        match self.kind {
            Kind::Usage => 2,
            Kind::Refused => 3,
            Kind::Failed => 1,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for Error {}

pub fn usage(reason: impl Into<String>) -> Error {
    Error { kind: Kind::Usage, reason: reason.into() }
}

pub fn refused(reason: impl Into<String>) -> Error {
    Error { kind: Kind::Refused, reason: reason.into() }
}

pub fn failed(reason: impl Into<String>) -> Error {
    Error { kind: Kind::Failed, reason: reason.into() }
}

/// A system call error (rustix) as a failure that names what was being done.
pub fn errno(what: impl fmt::Display, e: rustix::io::Errno) -> Error {
    failed(format!("{what}: {e}"))
}
