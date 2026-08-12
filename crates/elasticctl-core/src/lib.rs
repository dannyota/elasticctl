#![forbid(unsafe_code)]

pub mod auth;
pub mod capabilities;
pub mod config;
pub mod error;
pub mod transport;

pub use auth::Credential;
pub use capabilities::{Capabilities, Flavor};
pub use config::{Config, Overrides, Profile, Resolved, Source};
pub use error::{Error, ErrorKind, Result};
pub use transport::Transport;
