use std::{collections::BTreeMap, fs::read_to_string, num::TryFromIntError, path::PathBuf};

use jwt::{
    AlgorithmType, Claims, Header, PKeyWithDigest, RegisteredClaims, SignWithKey, Token,
    VerifyWithKey,
};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    rsa::Rsa,
};
use time::{Duration, OffsetDateTime};
use tracing::{debug, instrument};

use crate::domain::UserSpec;

use super::{Jwt, JwtEncoder, Result};

// Defaults

const DEFAULT_PRIVKEY: &str = "etc/privkey.pem";
const DEFAULT_VALIDITY: u32 = 24 * 60 * 60;

// Errors

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

// Data structs

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
pub struct DefaultJwtEncoderArgs {
    #[arg(
        long = "jwt-privkey",
        env = "JWT_PRIVKEY",
        name = "JWT_PRIVKEY",
        long_help = "Path to private key used to sign JWT",
        default_value = DEFAULT_PRIVKEY
    )]
    pub privkey: PathBuf,
    #[arg(
        long = "jwt-validity",
        env = "JWT_VALIDITY",
        name = "JWT_VALIDITY",
        long_help = "Number of seconds during which a JWT is valid",
        default_value_t = DEFAULT_VALIDITY,
    )]
    pub validity: u32,
}

impl Default for DefaultJwtEncoderArgs {
    fn default() -> Self {
        Self {
            privkey: DEFAULT_PRIVKEY.into(),
            validity: DEFAULT_VALIDITY,
        }
    }
}

// DefaultJwtEncoder

pub struct DefaultJwtEncoder {
    privkey: PKeyWithDigest<Private>,
    pubkey: PKeyWithDigest<Public>,
    validity: Duration,
}

impl DefaultJwtEncoder {
    pub fn new(args: DefaultJwtEncoderArgs) -> anyhow::Result<Self> {
        debug!("loading private key");
        let pem = read_to_string(args.privkey)?;
        let privkey = Rsa::private_key_from_pem(pem.as_bytes())?;
        debug!("computing public key from private");
        let n = privkey.n().to_owned()?;
        let e = privkey.e().to_owned()?;
        let pubkey = Rsa::from_public_components(n, e)?;
        let digest = MessageDigest::sha384();
        Ok(Self {
            privkey: PKeyWithDigest {
                digest,
                key: PKey::from_rsa(privkey)?,
            },
            pubkey: PKeyWithDigest {
                digest,
                key: PKey::from_rsa(pubkey)?,
            },
            validity: Duration::seconds(args.validity.into()),
        })
    }
}

impl JwtEncoder for DefaultJwtEncoder {
    #[instrument("decode_jwt", skip(self, jwt))]
    fn decode(&self, jwt: &str) -> Result<String> {
        debug!("verifying jwt");
        let claims: Claims = jwt.verify_with_key(&self.pubkey)?;
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

    #[instrument("encode_jwt", skip(self, name, user), fields(user.name = name))]
    fn encode(&self, name: &str, user: &UserSpec) -> Result<Jwt> {
        debug!("encoding jwt");
        let expiration = OffsetDateTime::now_utc() + self.validity;
        let expiration_ts: u64 = expiration.unix_timestamp().try_into()?;
        let header = Header {
            algorithm: AlgorithmType::Rs384,
            ..Default::default()
        };
        let claims = Claims {
            private: BTreeMap::from_iter([("email".into(), user.email.clone().into())]),
            registered: RegisteredClaims {
                expiration: Some(expiration_ts),
                subject: Some(name.into()),
                ..Default::default()
            },
        };
        let token = Token::new(header, claims).sign_with_key(&self.privkey)?;
        Ok(Jwt {
            expiration,
            token: token.as_str().to_string(),
            validity: self.validity,
        })
    }
}

// super::Error

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
