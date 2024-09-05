use std::{
    fs::{create_dir_all, File},
    path::PathBuf,
};

use clap::Parser;
use kube::CustomResourceExt;
use simpaas_core::{tracer::init_tracer, Service, ServiceInstance};
use tracing::debug;

// Main

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    init_tracer(args.log_filter)?;
    debug!("creating output directory");
    create_dir_all(&args.output)?;
    let crds = [
        ("service", Service::crd()),
        ("service-instance", ServiceInstance::crd()),
    ];
    for (name, crd) in crds {
        debug!("dumping yaml-formatted crd to file");
        let mut file = File::create(args.output.join(name).with_extension("yaml"))?;
        serde_yaml::to_writer(&mut file, &crd)?;
    }
    Ok(())
}

// Args

#[derive(Clone, Debug, Eq, Parser, PartialEq)]
struct Args {
    #[arg(
        long,
        env,
        default_value = "crds=info,warn",
        long_help = "Log filter (https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#directives)"
    )]
    log_filter: String,
    #[arg(help = "Path to directory into write CRDs files")]
    output: PathBuf,
}
