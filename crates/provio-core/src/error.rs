//! Error type shared across all provio crates.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProvioError {
    #[error("policy error: {0}")]
    Policy(String),

    #[error("ledger error: {0}")]
    Ledger(String),

    #[error("sandbox error: {0}")]
    Sandbox(String),

    #[error("interception error: {0}")]
    Intercept(String),

    #[error("approval error: {0}")]
    Approval(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, ProvioError>;
