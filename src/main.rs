use std::{
    io::{stderr, stdout},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
};

use ::kube::CustomResourceExt;
use api::{start_api, ApiContext};
use clap::{Parser, Subcommand};
use cmd::default::DefaultCommandRunner;
use deploy::helm::{HelmDeployer, HelmDeployerArgs};
use domain::{App, Invitation, Role, User};
use helm::default::{DefaultHelmClient, DefaultHelmClientArgs};
use jwt::default::{DefaultJwtEncoder, DefaultJwtEncoderArgs};
use kube::default::{DefaultKubeClient, DefaultKubeEventPublisher};
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

// Mods

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

// Bin

const CARGO_PKG_NAME: &str = env!("CARGO_PKG_NAME");

// Defaults

const DEFAULT_APP_STATUS_DELAY: u64 = 30;
const DEFAULT_BIND_ADDR: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 8080));
const DEFAULT_DOMAIN: &str = "127.0.0.1";
const DEFAULT_RETRY_DELAY: u64 = 10;
const DEFAULT_ROOT_PATH: &str = "/";
const DEFAULT_WEBAPP_URL: &str = "http://localhost:3000";

// CLI

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct ApiArgs {
    #[arg(
        long,
        env,
        default_value_t = DEFAULT_BIND_ADDR,
        long_help = "Address on which listen requests"
    )]
    bind_addr: SocketAddr,
    #[command(flatten)]
    cookie: CookieArgs,
    #[command(flatten)]
    jwt: DefaultJwtEncoderArgs,
    #[arg(long, env, default_value = DEFAULT_ROOT_PATH, long_help = "Root endpoints path")]
    root_path: String,
}

impl Default for ApiArgs {
    fn default() -> Self {
        Self {
            bind_addr: DEFAULT_BIND_ADDR,
            cookie: Default::default(),
            jwt: DefaultJwtEncoderArgs::default(),
            root_path: DEFAULT_ROOT_PATH.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, Parser, PartialEq)]
#[command(version)]
struct Args {
    #[command(subcommand)]
    cmd: Command,
    #[command(flatten)]
    obs: ObsArgs,
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
struct CookieArgs {
    #[arg(
        long,
        env,
        default_value = DEFAULT_DOMAIN,
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
            domain: DEFAULT_DOMAIN.into(),
            http_only_disabled: false,
            secure_disabled: false,
        }
    }
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
struct DelayArgs {
    #[arg(
        long = "app-status-delay",
        env = "APP_STATUS_DELAY",
        name = "APP_STATUS_DELAY",
        default_value_t = DEFAULT_APP_STATUS_DELAY,
        long_help = "Number of seconds between check app status"
    )]
    app_status: u64,
    #[arg(
        long = "retry-delay",
        env = "RETRY_DELAY",
        name = "RETRY_DELAY",
        default_value_t = DEFAULT_RETRY_DELAY,
        long_help = "Number of seconds to wait after a failure"
    )]
    retry: u64,
}

impl Default for DelayArgs {
    fn default() -> Self {
        Self {
            app_status: DEFAULT_APP_STATUS_DELAY,
            retry: DEFAULT_RETRY_DELAY,
        }
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

#[derive(clap::Args, Clone, Debug, Eq, PartialEq)]
struct OpArgs {
    #[command(flatten)]
    delays: DelayArgs,
    #[command(flatten)]
    deployer: HelmDeployerArgs,
    #[command(flatten)]
    helm: DefaultHelmClientArgs,
    #[arg(long, env, long_help = "Name of current instance")]
    instance: Option<String>,
    #[command(flatten)]
    mail: DefaultMailSenderArgs,
    #[arg(
        long,
        env,
        default_value = DEFAULT_WEBAPP_URL,
        long_help = "WebApp URL"
    )]
    webapp_url: String,
}

impl Default for OpArgs {
    fn default() -> Self {
        Self {
            delays: Default::default(),
            deployer: Default::default(),
            helm: Default::default(),
            instance: None,
            mail: DefaultMailSenderArgs::default(),
            webapp_url: DEFAULT_WEBAPP_URL.into(),
        }
    }
}

// SignalListener

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

// Main

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
                kube: DefaultKubeClient::new(kube),
                pwd_encoder: BcryptPasswordEncoder,
            };
            start_api(args.bind_addr, &args.root_path, ctx).await
        }
        Command::Crd { cmd } => cmd.print(),
        Command::Op(args) => {
            let kube = ::kube::Client::try_default().await?;
            let helm = DefaultHelmClient::new(args.helm, DefaultCommandRunner);
            let ctx = OpContext {
                delays: args.delays.into(),
                deployer: HelmDeployer::new(args.deployer, helm),
                kube: DefaultKubeClient::new(kube.clone()),
                mail_sender: DefaultMailSender::new(args.mail, args.webapp_url)?,
                publisher: DefaultKubeEventPublisher::new(kube.clone(), args.instance),
            };
            start_op(kube, ctx).await
        }
    }
}

// Fns

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
