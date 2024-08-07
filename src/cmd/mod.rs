use std::{ffi::OsStr, process::Output};

use futures::Future;

// Mods

pub mod default;

// Types

pub type Result<T = ()> = std::result::Result<T, Error>;

// Errors

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("command failed")]
    Failure(Output),
    #[error("i/o error: {0}")]
    Io(
        #[from]
        #[source]
        std::io::Error,
    ),
}

// Traits

pub trait CommandRunner: Send + Sync {
    fn run<S: AsRef<OsStr> + Send + Sync>(
        &self,
        cmd: &str,
        args: &[S],
    ) -> impl Future<Output = Result<Output>> + Send;
}
