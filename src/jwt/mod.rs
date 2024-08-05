use time::{Duration, OffsetDateTime};

use crate::domain::UserSpec;

// Mods

pub mod default;

// Types

pub type Result<T = ()> = std::result::Result<T, Error>;

// Errors

#[derive(Debug, thiserror::Error)]
#[error("jwt error: {0}")]
pub struct Error(#[source] pub Box<dyn std::error::Error + Send + Sync>);

// Data structs

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Jwt {
    pub expiration: OffsetDateTime,
    pub token: String,
    pub validity: Duration,
}

// Traits

pub trait JwtEncoder: Send + Sync {
    fn decode(&self, jwt: &str) -> Result<String>;

    fn encode(&self, name: &str, user: &UserSpec) -> Result<Jwt>;
}
