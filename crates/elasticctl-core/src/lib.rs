#![forbid(unsafe_code)]

pub mod config;
pub mod error;

pub use config::{Config, Overrides, Profile, Resolved, Source};
pub use error::{Error, ErrorKind, Result};
