//! One module per subcommand.
//!
//! `main` is for parsing arguments and dispatching; what each command actually
//! does lives here. Before this split, `async fn main` was 438 lines and the
//! `fairness` arm alone was 314 of them.

pub mod fairness;
pub mod setup;
pub mod verify;

/// What the command modules need from the crate root.
///
/// The CLI types stay in `main.rs` beside their clap derives, which is where
/// they read best against the `--help` output they generate.
pub(crate) mod prelude {
    pub(crate) use std::sync::Arc;

    pub(crate) use crate::assessment::TenantClusterConfig;
    pub(crate) use crate::cluster::KubernetesClient;
    pub(crate) use crate::{
        setup_logging, setup_test_environment, FairnessCliLayer, FairnessConfigBuilder,
        RateLimitStrategy, SetupArgs, SolutionUnderTest, VerifyArgs,
    };
}
