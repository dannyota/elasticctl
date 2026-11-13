use elasticctl_core::{Result, Transport};

pub(crate) async fn value_lists_bootstrapped(t: &Transport) -> Result<bool> {
    Ok(super::bootstrap_state(t).await?.ready())
}
