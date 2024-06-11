use liquid::{object, Parser, Template};
use mail_send::{mail_builder::MessageBuilder, SmtpClientBuilder};
use tracing::{debug, instrument};

use crate::{api::PATH_JOIN, kube::Invitation};

use super::{MailSender, Result};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("liquid error: {0}")]
    Liquid(
        #[from]
        #[source]
        liquid::Error,
    ),
    #[error("{0}")]
    Mail(
        #[from]
        #[source]
        mail_send::Error,
    ),
}

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
pub struct DefaultMailSenderArgs {
    #[arg(
        long = "smtp-from",
        env = "SMTP_FROM",
        name = "SMTP_FROM",
        default_value = "noreply@simpaas.gleroy.dev",
        long_help = "Email address used to send mail"
    )]
    pub from: String,
    #[arg(
        long = "smtp-host",
        env = "SMTP_HOST",
        name = "SMTP_HOST",
        default_value = "127.0.0.1",
        long_help = "SMTP server address"
    )]
    pub host: String,
    #[arg(
        long = "smtp-implicit-tls",
        env = "SMTP_IMPLICIT_TLS",
        name = "SMTP_IMPLICIT_TLS",
        default_value_t = false,
        long_help = "Enable SMTP implicit TLS"
    )]
    pub implicit_tls: bool,
    #[arg(
        long = "smtp-password",
        env = "SMTP_PASSWORD",
        name = "SMTP_PASSWORD",
        long_help = "SMTP password"
    )]
    pub password: Option<String>,
    #[arg(
        long = "smtp-port",
        env = "SMTP_PORT",
        name = "SMTP_PORT",
        default_value_t = 25,
        long_help = "SMTP server port"
    )]
    pub port: u16,
    #[arg(
        long = "smtp-tls",
        env = "SMTP_TLS",
        name = "SMTP_TLS",
        default_value_t = false,
        long_help = "Enable SMTP TLS"
    )]
    pub tls: bool,
    #[arg(
        long = "smtp-user",
        env = "SMTP_USER",
        name = "SMTP_USER",
        long_help = "SMTP user"
    )]
    pub user: Option<String>,
}

impl Default for DefaultMailSenderArgs {
    fn default() -> Self {
        Self {
            from: "noreply@simpaas.gleroy.dev".into(),
            host: "127.0.0.1".into(),
            implicit_tls: false,
            password: None,
            port: 25,
            tls: false,
            user: None,
        }
    }
}

pub struct DefaultMailSender {
    args: DefaultMailSenderArgs,
    invit_tpl: Template,
    webapp_url: String,
}

impl DefaultMailSender {
    pub fn new(args: DefaultMailSenderArgs, webapp_url: String) -> anyhow::Result<Self> {
        let parser = Parser::new();
        debug!("parsing invitation template");
        let invit_tpl = parser.parse(include_str!(
            "../../resources/main/mail/invitation.html.liquid"
        ))?;
        Ok(Self {
            args,
            invit_tpl,
            webapp_url,
        })
    }

    async fn send(&self, msg: MessageBuilder<'_>) -> Result {
        let mut builder = SmtpClientBuilder::new(self.args.host.as_str(), self.args.port)
            .implicit_tls(self.args.implicit_tls);
        if let Some(pwd) = &self.args.password {
            let user = self.args.user.as_deref().unwrap_or(&self.args.from);
            builder = builder.credentials((user, pwd.as_str()));
        }
        if self.args.tls {
            debug!("connecting smtp tls client");
            let mut client = builder.connect().await?;
            debug!("sending mail");
            client.send(msg).await?;
        } else {
            debug!("connecting smtp plain client");
            let mut client = builder.connect_plain().await?;
            debug!("sending mail");
            client.send(msg).await?;
        }
        Ok(())
    }
}

impl MailSender for DefaultMailSender {
    #[instrument("send_invitation_mail", skip(self, invit), fields(invit.to = invit.spec.to, invit.token = token))]
    async fn send_invitation(&self, token: &str, invit: &Invitation) -> Result {
        let html = self.invit_tpl.render(&object!({
            "link": format!("{}{PATH_JOIN}/{token}", self.webapp_url),
            "user": &invit.spec.from,
        }))?;
        let msg = MessageBuilder::new()
            .from((self.args.from.as_str(), self.args.from.as_str()))
            .to((invit.spec.to.as_str(), invit.spec.to.as_str()))
            .subject("Join SimPaaS!")
            .html_body(&html);
        self.send(msg).await
    }
}

impl From<Error> for super::Error {
    fn from(err: Error) -> Self {
        Self(Box::new(err))
    }
}

impl From<liquid::Error> for super::Error {
    fn from(err: liquid::Error) -> Self {
        Error::Liquid(err).into()
    }
}

impl From<mail_send::Error> for super::Error {
    fn from(err: mail_send::Error) -> Self {
        Error::Mail(err).into()
    }
}
