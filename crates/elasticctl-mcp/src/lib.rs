#![forbid(unsafe_code)]

mod bounded_io;
pub mod catalog;
mod error;
mod mutation;
mod plan;
mod prompts;
mod resources;
pub mod result;
pub mod server;
pub mod tools;

pub use mutation::{MutationClass, MutationClasses};
pub use result::{PageInfo, TargetContext, ToolError, ToolFailure, ToolSuccess};
pub use server::{ServerOptions, ServerState, serve_io, serve_stdio, validate_startup};
