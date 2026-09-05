#![forbid(unsafe_code)]

mod bounded_io;
pub mod catalog;
mod error;
pub mod result;
pub mod server;
pub mod tools;

pub use result::{PageInfo, TargetContext, ToolError, ToolFailure, ToolSuccess};
pub use server::{ServerOptions, ServerState, serve_io, serve_stdio};
