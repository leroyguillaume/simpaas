use futures::Future;

use crate::domain::Invitation;

pub mod default;

pub type Result<T = ()> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
#[error("mail error: {0}")]
pub struct Error(#[source] pub Box<dyn std::error::Error + Send + Sync>);

pub trait MailSender: Send + Sync {
    fn send_invitation(
        &self,
        token: &str,
        invit: &Invitation,
    ) -> impl Future<Output = Result> + Send;
}
