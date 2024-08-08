use clap::Parser;
use simpaas_core::tracer::init_tracer;

// Main

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    init_tracer(args.log_filter)?;
    Ok(())
}

// Args

#[derive(Clone, Debug, Eq, Parser, PartialEq)]
#[command(version)]
struct Args {
    #[arg(
        long,
        env,
        default_value = "simpaas_api=info,simpaas_core=info,warn",
        long_help = "Log filter (https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#directives)"
    )]
    log_filter: String,
}
