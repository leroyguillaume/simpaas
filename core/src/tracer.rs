use std::io::stderr;

use tracing_subscriber::{
    filter::ParseError,
    fmt::layer,
    layer::SubscriberExt,
    registry,
    util::{SubscriberInitExt, TryInitError},
    EnvFilter,
};

// Types

pub type Result<T = ()> = std::result::Result<T, Error>;

// Error

#[derive(Debug, thiserror::Error)]
#[error("failed to initialize tracer: {0}")]
pub enum Error {
    Init(
        #[from]
        #[source]
        TryInitError,
    ),
    Filter(
        #[from]
        #[source]
        ParseError,
    ),
}

// Functions

pub fn init_tracer<FILTER: Into<String>>(log_filter: FILTER) -> Result {
    let filter = EnvFilter::builder().parse(log_filter.into())?;
    let sub = layer().with_writer(stderr);
    registry().with(filter).with(sub).try_init()?;
    Ok(())
}
