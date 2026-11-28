//! What differs per operating system: where things live and how services start. Only macOS is installed by this
//! release; the shared steps (records, release, certificates, bootstrap, status) do not depend on it.

pub mod macos;
