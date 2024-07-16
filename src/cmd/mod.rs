use std::{ffi::OsStr, process::Output};

use futures::Future;

pub mod default;

pub type Result<T = ()> = std::result::Result<T, Error>;

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

pub trait CommandRunner: Send + Sync {
    fn run<S: AsRef<OsStr> + Send + Sync>(
        &self,
        cmd: &str,
        args: &[S],
    ) -> impl Future<Output = Result<Output>> + Send;
}
