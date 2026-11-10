//! Fixture recorder: drive a live stack and write scrubbed exchanges.
//!
//! Fixtures capture what Elastic sent. Hand-written mocks capture assumptions,
//! which is where API bugs hide.

mod activation;
mod conformance;
mod conformance_matrix;

pub(crate) mod clock;
pub(crate) mod diagnostics;
pub(crate) mod environment;
pub(crate) mod fixtures;
pub(crate) mod recorder;
pub(crate) mod scrub;
pub(crate) mod seed;

use crate::recorder::record;
use crate::seed::seed;
pub(crate) use seed::converge_prebuilt_rules;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("record") => record().await,
        Some("record-compose") => recorder::compose::record_compose().await,
        Some("seed") => seed().await,
        Some("conformance") => {
            if let Err(error) = conformance::run(&args[1..]).await {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        Some("conformance-matrix") => {
            if let Err(error) = conformance_matrix::run(&args[1..]).await {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!(
                "usage: cargo xtask [record|record-compose|seed|conformance|conformance-matrix]"
            );
            std::process::exit(2);
        }
    }
}
