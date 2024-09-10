// Types

use std::string::FromUtf8Error;

pub type Result<VALUE = ()> = std::result::Result<VALUE, Error>;

// Error

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("command failed")]
    CommandFailed,
    #[error("i/o error: {0}")]
    Io(
        #[from]
        #[source]
        std::io::Error,
    ),
    #[error("liquid error: {0}")]
    Liquid(
        #[from]
        #[source]
        liquid::Error,
    ),
    #[error("kubernetes error: {0}")]
    Kube(
        #[from]
        #[source]
        kube::Error,
    ),
    #[error("service doesn't consume this kind of resource")]
    ResourceNotConsumed,
    #[error("service instance doesn't exist")]
    ServiceInstanceNotFound,
    #[error("service doesn't exist")]
    ServiceNotFound,
    #[error("job doesn't have name")]
    UnnamedJob,
    #[error("resource doesn't have name")]
    UnnamedResource,
    #[error("resource doesn't have namespace")]
    UnnamespacedResource,
    #[error("utf8 error: {0}")]
    Utf8(
        #[from]
        #[source]
        FromUtf8Error,
    ),
    #[error("yaml error: {0}")]
    Yaml(
        #[from]
        #[source]
        serde_yaml::Error,
    ),
}
