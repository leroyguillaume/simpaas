// Mods

pub mod bcrypt;

// Types

pub type Result<T = ()> = std::result::Result<T, Error>;

// Errors

#[derive(Debug, thiserror::Error)]
#[error("password error: {0}")]
pub struct Error(#[source] pub Box<dyn std::error::Error + Send + Sync>);

// Traits

pub trait PasswordEncoder: Send + Sync {
    fn encode(&self, password: &str) -> Result<String>;

    fn verify(&self, password: &str, hash: &str) -> Result<bool>;
}
