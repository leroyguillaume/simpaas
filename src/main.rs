use std::{
    io::{stderr, stdout},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use ::kube::CustomResourceExt;
use api::{start_api, ApiContext};
use clap::{Parser, Subcommand};
use cmd::default::DefaultCommandRunner;
use deploy::helm::{HelmDeployer, HelmDeployerArgs};
use domain::{App, Invitation, Role, User};
use helm::cli::{CliHelmClient, CliHelmClientArgs};
use jwt::default::{DefaultJwtEncoder, DefaultJwtEncoderArgs};
use kube::api::{ApiKubeClient, ApiKubeEventPublisher};
use mail::default::{DefaultMailSender, DefaultMailSenderArgs};
use op::{start_op, OpContext};
use opentelemetry::KeyValue;
use opentelemetry_otlp::{new_exporter, new_pipeline, WithExportConfig};
use opentelemetry_sdk::{
    runtime::Tokio,
    trace::{BatchConfig, Config, RandomIdGenerator, Sampler},
    Resource,
};
use opentelemetry_semantic_conventions::{
    resource::{SERVICE_NAME, SERVICE_VERSION},
    SCHEMA_URL,
};
use pwd::bcrypt::BcryptPasswordEncoder;
use tokio::{
    select,
    signal::unix::{signal, Signal, SignalKind},
};
use tracing::debug;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{
    fmt::layer, layer::SubscriberExt, registry, util::SubscriberInitExt, EnvFilter,
};

mod api;
mod cmd;
mod deploy;
mod domain;
mod helm;
mod jwt;
mod kube;
mod mail;
mod op;
mod pwd;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    init_tracing(args.obs)?;
    match args.cmd {
        Command::Api(args) => {
            let kube = ::kube::Client::try_default().await?;
            let ctx = ApiContext {
                cookie: args.cookie,
                jwt_encoder: DefaultJwtEncoder::new(args.jwt)?,
                kube: ApiKubeClient::new(kube),
                pwd_encoder: BcryptPasswordEncoder,
            };
            start_api(args.bind_addr, &args.root_path, ctx).await
        }
        Command::Crd { cmd } => cmd.print(),
        Command::Op(args) => {
            let kube = ::kube::Client::try_default().await?;
            let helm = CliHelmClient::new(args.helm, DefaultCommandRunner);
            let ctx = OpContext {
                deployer: HelmDeployer::new(args.deployer, helm),
                kube: ApiKubeClient::new(kube.clone()),
                mail_sender: DefaultMailSender::new(args.mail, args.webapp_url)?,
                publisher: ApiKubeEventPublisher::new(kube.clone(), args.instance),
                requeue_delay: Duration::from_secs(args.requeue_delay),
            };
            start_op(kube, ctx).await
        }
    }
}

const CARGO_PKG_NAME: &str = env!("CARGO_PKG_NAME");

#[derive(Clone, Debug, Eq, Parser, PartialEq)]
#[command(version)]
struct Args {
    #[command(subcommand)]
    cmd: Command,
    #[command(flatten)]
    obs: ObsArgs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Subcommand)]
enum CrdCommand {
    #[command(about = "Print App CRD")]
    App,
    #[command(about = "Print Invitation CRD", alias = "invit")]
    Invitation,
    #[command(about = "Print Role CRD")]
    Role,
    #[command(about = "Print User CRD")]
    User,
}

impl CrdCommand {
    fn print(self) -> anyhow::Result<()> {
        let crd = match self {
            Self::App => App::crd(),
            Self::Invitation => Invitation::crd(),
            Self::Role => Role::crd(),
            Self::User => User::crd(),
        };
        serde_yaml::to_writer(stdout(), &crd)?;
        Ok(())
    }
}

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct ObsArgs {
    #[arg(
        long,
        env,
        default_value = "simpaas=info,warn",
        long_help = "Log filter (https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#directives)"
    )]
    log_filter: String,
    #[arg(long, env, long_help = "URL to OTEL collector")]
    otel_collector_url: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
enum Command {
    #[command(about = "Start API server")]
    Api(ApiArgs),
    #[command(about = "Print CRD")]
    Crd {
        #[command(subcommand)]
        cmd: CrdCommand,
    },
    #[command(about = "Start operator")]
    Op(OpArgs),
}

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct ApiArgs {
    #[arg(
        long,
        env,
        default_value = "0.0.0.0:8080",
        long_help = "Address on which listen requests"
    )]
    bind_addr: SocketAddr,
    #[command(flatten)]
    cookie: CookieArgs,
    #[command(flatten)]
    jwt: DefaultJwtEncoderArgs,
    #[arg(long, env, default_value = "/", long_help = "Root endpoints path")]
    root_path: String,
}

impl Default for ApiArgs {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 8080)),
            cookie: Default::default(),
            jwt: DefaultJwtEncoderArgs::default(),
            root_path: "/".into(),
        }
    }
}

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct CookieArgs {
    #[arg(
        long,
        env,
        default_value = "127.0.0.1",
        long_help = "Domain used to create cookies"
    )]
    domain: String,
    #[arg(
        long = "cookie-http-only-disabled",
        env = "COOKIE_HTTP_ONLY_DISABLED",
        long_help = "Disable http-only on cookies"
    )]
    http_only_disabled: bool,
    #[arg(
        long = "cookie-secure-disabled",
        env = "COOKIE_SECURE_DISABLED",
        long_help = "Disable secure on cookies"
    )]
    secure_disabled: bool,
}

impl Default for CookieArgs {
    fn default() -> Self {
        Self {
            domain: "127.0.0.1".into(),
            http_only_disabled: false,
            secure_disabled: false,
        }
    }
}

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct OpArgs {
    #[command(flatten)]
    deployer: HelmDeployerArgs,
    #[command(flatten)]
    helm: CliHelmClientArgs,
    #[arg(long, env, long_help = "Name of current instance")]
    instance: Option<String>,
    #[command(flatten)]
    mail: DefaultMailSenderArgs,
    #[arg(
        long,
        env,
        default_value_t = 10,
        long_help = "Number of seconds between CRD check"
    )]
    requeue_delay: u64,
    #[arg(
        long,
        env,
        default_value = "http://localhost:3000",
        long_help = "WebApp URL"
    )]
    webapp_url: String,
}

impl Default for OpArgs {
    fn default() -> Self {
        Self {
            deployer: Default::default(),
            helm: Default::default(),
            instance: None,
            mail: DefaultMailSenderArgs::default(),
            requeue_delay: 10,
            webapp_url: "http://localhost:3000".into(),
        }
    }
}

struct SignalListener {
    int: Signal,
    term: Signal,
}

impl SignalListener {
    fn new() -> std::io::Result<Self> {
        Ok(Self {
            int: signal(SignalKind::interrupt())?,
            term: signal(SignalKind::terminate())?,
        })
    }

    async fn recv(&mut self) {
        select! {
            _ = self.int.recv() => {
                debug!("sigint received");
            }
            _ = self.term.recv() => {
                debug!("sigterm received")
            }
        }
    }
}

fn init_tracing(args: ObsArgs) -> anyhow::Result<()> {
    let filter = EnvFilter::builder().parse(args.log_filter)?;
    let sub = layer().with_writer(stderr);
    let registry = registry().with(filter).with(sub);
    if let Some(otel_url) = args.otel_collector_url {
        let res = Resource::from_schema_url(
            [
                KeyValue::new(SERVICE_NAME, CARGO_PKG_NAME),
                KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
            ],
            SCHEMA_URL,
        );
        let cfg = Config::default()
            .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
                1.0,
            ))))
            .with_id_generator(RandomIdGenerator::default())
            .with_resource(res);
        let exp = new_exporter().tonic().with_endpoint(otel_url);
        let tracer = new_pipeline()
            .tracing()
            .with_trace_config(cfg)
            .with_batch_config(BatchConfig::default())
            .with_exporter(exp)
            .install_batch(Tokio)?;
        registry.with(OpenTelemetryLayer::new(tracer)).try_init()?;
    } else {
        registry.try_init()?;
    }
    Ok(())
}
