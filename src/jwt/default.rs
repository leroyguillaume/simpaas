use std::num::TryFromIntError;

use hmac::{Hmac, Mac};
use jwt::{AlgorithmType, Claims, Header, RegisteredClaims, SignWithKey, Token, VerifyWithKey};
use sha2::Sha384;
use time::{Duration, OffsetDateTime};
use tracing::{debug, instrument};

use super::{Jwt, JwtEncoder, Result};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Jwt(
        #[from]
        #[source]
        ::jwt::Error,
    ),
    #[error("jwt is invalid")]
    InvalidJwt,
    #[error("time error: {0}")]
    Time(
        #[from]
        #[source]
        TryFromIntError,
    ),
}

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
pub struct DefaultJwtEncoderArgs {
    #[arg(
        long = "jwt-secret",
        env = "JWT_SECRET",
        name = "JWT_SECRET",
        long_help = "Secret used to sign JWT"
    )]
    pub secret: String,
    #[arg(
        long = "jwt-validity",
        env = "JWT_VALIDITY",
        name = "JWT_VALIDITY",
        long_help = "Number of seconds during which a JWT is valid",
        default_value_t = 24 * 60 * 60,
    )]
    pub validity: u32,
}

impl Default for DefaultJwtEncoderArgs {
    fn default() -> Self {
        Self {
            secret: "changeit".into(),
            validity: 24 * 60 * 60,
        }
    }
}

pub struct DefaultJwtEncoder {
    key: Hmac<Sha384>,
    validity: Duration,
}

impl DefaultJwtEncoder {
    pub fn new(args: DefaultJwtEncoderArgs) -> anyhow::Result<Self> {
        debug!("generating hmac key from secret");
        let key = Hmac::new_from_slice(args.secret.as_bytes())?;
        Ok(Self {
            key,
            validity: Duration::seconds(args.validity.into()),
        })
    }
}

impl JwtEncoder for DefaultJwtEncoder {
    #[instrument("decode_jwt", skip(self, jwt))]
    fn decode(&self, jwt: &str) -> Result<String> {
        debug!("verifying jwt");
        let claims: Claims = jwt.verify_with_key(&self.key)?;
        let now_ts: u64 = OffsetDateTime::now_utc().unix_timestamp().try_into()?;
        let expiration_ts = claims.registered.expiration.ok_or_else(|| {
            debug!("jwt doesn't contain expiration");
            Error::InvalidJwt
        })?;
        if expiration_ts < now_ts {
            debug!("jwt is expired");
            return Err(Error::InvalidJwt.into());
        }
        let subj = claims.registered.subject.ok_or_else(|| {
            debug!("jwt doesn't contain subject");
            Error::InvalidJwt
        })?;
        Ok(subj)
    }

    #[instrument("encode_jwt", skip(self, name), fields(user.name = name))]
    fn encode(&self, name: &str) -> Result<Jwt> {
        debug!("encoding jwt");
        let expiration = OffsetDateTime::now_utc() + self.validity;
        let expiration_ts: u64 = expiration.unix_timestamp().try_into()?;
        let header = Header {
            algorithm: AlgorithmType::Hs384,
            ..Default::default()
        };
        let claims = Claims {
            registered: RegisteredClaims {
                expiration: Some(expiration_ts),
                subject: Some(name.into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let token = Token::new(header, claims).sign_with_key(&self.key)?;
        Ok(Jwt {
            expiration,
            token: token.as_str().to_string(),
            validity: self.validity,
        })
    }
}

impl From<Error> for super::Error {
    fn from(err: Error) -> Self {
        Self(Box::new(err))
    }
}

impl From<jwt::Error> for super::Error {
    fn from(err: jwt::Error) -> Self {
        Error::Jwt(err).into()
    }
}

impl From<TryFromIntError> for super::Error {
    fn from(err: TryFromIntError) -> Self {
        Error::Time(err).into()
    }
}
