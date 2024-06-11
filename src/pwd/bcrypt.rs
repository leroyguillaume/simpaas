use bcrypt::BcryptError;
use tracing::{debug, instrument};

use super::{Error, PasswordEncoder, Result};

pub struct BcryptPasswordEncoder;

impl PasswordEncoder for BcryptPasswordEncoder {
    #[instrument("encode_password", skip(self, password))]
    fn encode(&self, password: &str) -> Result<String> {
        debug!("encoding password");
        bcrypt::hash(password, bcrypt::DEFAULT_COST).map_err(Error::from)
    }

    #[instrument("verify_password", skip(self, password, hash))]
    fn verify(&self, password: &str, hash: &str) -> Result<bool> {
        debug!("verifying password");
        bcrypt::verify(password, hash).map_err(Error::from)
    }
}

impl From<BcryptError> for Error {
    fn from(err: BcryptError) -> Self {
        Self(Box::new(err))
    }
}
