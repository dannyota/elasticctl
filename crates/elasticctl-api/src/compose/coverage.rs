//! Read-only report entry point.
use elasticctl_core::{Error, ErrorKind, Result, Transport};
pub async fn run(_t: &Transport) -> Result<()> {
    Err(Error::new(ErrorKind::Unsupported, "not implemented"))
}
