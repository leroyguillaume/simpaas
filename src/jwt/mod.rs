use time::{Duration, OffsetDateTime};

use crate::domain::UserSpec;

pub mod default;

pub type Result<T = ()> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
#[error("jwt error: {0}")]
pub struct Error(#[source] pub Box<dyn std::error::Error + Send + Sync>);

pub struct Jwt {
    pub expiration: OffsetDateTime,
    pub token: String,
    pub validity: Duration,
}

pub trait JwtEncoder: Send + Sync {
    fn decode(&self, jwt: &str) -> Result<String>;

    fn encode(&self, name: &str, user: &UserSpec) -> Result<Jwt>;
}
