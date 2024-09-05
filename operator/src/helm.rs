use std::{future::Future, path::Path};

use tracing::{debug, instrument};

use crate::{
    cmd::{CommandRunner, DefaultCommandRunner},
    err::Result,
};

// Traits

#[cfg_attr(test, mockall::automock)]
pub trait HelmRunner: Send + Sync {
    fn upgrade<'a>(
        &self,
        ns: &str,
        release: &str,
        chart: &str,
        values_filepath: &Path,
        version: Option<&'a str>,
    ) -> impl Future<Output = Result> + Send;

    fn uninstall(&self, ns: &str, release: &str) -> impl Future<Output = Result> + Send;
}

// DefaultHelmRunner

pub struct DefaultHelmRunner<RUNNER: CommandRunner> {
    bin: String,
    runner: RUNNER,
}

impl DefaultHelmRunner<DefaultCommandRunner> {
    pub fn new(bin: String) -> Self {
        Self {
            bin,
            runner: DefaultCommandRunner,
        }
    }
}

impl<RUNNER: CommandRunner> HelmRunner for DefaultHelmRunner<RUNNER> {
    #[instrument(skip(self, ns, release, chart, values_filepath), fields(release.chart = chart, release.name = release, release.namespace = ns))]
    async fn upgrade<'a>(
        &self,
        ns: &str,
        release: &str,
        chart: &str,
        values_filepath: &Path,
        version: Option<&'a str>,
    ) -> Result {
        let values_filepath = values_filepath.to_string_lossy();
        let mut args = vec![
            "upgrade",
            "--install",
            "--create-namespace",
            "-n",
            ns,
            "--values",
            values_filepath.as_ref(),
        ];
        if let Some(version) = version {
            args.extend_from_slice(&["--version", version]);
        }
        args.extend_from_slice(&[release, chart]);
        debug!("upgrading helm release");
        self.runner.run(&self.bin, &args).await?;
        debug!("helm release successfully upgraded");
        Ok(())
    }

    #[instrument(skip(self, ns, release), fields(release.name = release, release.namespace = ns))]
    async fn uninstall(&self, ns: &str, release: &str) -> Result {
        debug!("uninstalling helm release");
        self.runner
            .run(
                &self.bin,
                &["uninstall", "--ignore-not-found", "-n", ns, release],
            )
            .await?;
        debug!("helm release successfully uninstalled");
        Ok(())
    }
}

// Tests

#[cfg(test)]
mod test {
    use crate::{cmd::MockCommandRunner, test::*};

    use super::*;

    // Mods

    mod default_helm_installer {
        use super::*;

        // Mods

        mod upgrade {
            use super::*;

            // Data

            #[derive(Clone)]
            struct Data {
                args: Vec<String>,
                bin: &'static str,
                chart: &'static str,
                namespace: &'static str,
                release: &'static str,
                values_filepath: &'static Path,
                version: Option<&'static str>,
            }

            impl Default for Data {
                fn default() -> Self {
                    let chart = "chart";
                    let ns = "namespace";
                    let release = "release";
                    let values_filepath = Path::new("values");
                    Self {
                        args: vec![
                            "upgrade".into(),
                            "--install".into(),
                            "--create-namespace".into(),
                            "-n".into(),
                            ns.into(),
                            "--values".into(),
                            values_filepath.to_str().unwrap().into(),
                            release.into(),
                            chart.into(),
                        ],
                        bin: "helm",
                        chart,
                        namespace: ns,
                        release,
                        values_filepath,
                        version: None,
                    }
                }
            }

            // Tests

            async fn test(data: Data) {
                init_tracer();
                let mut runner = MockCommandRunner::new();
                runner
                    .expect_run()
                    .withf({
                        let data = data.clone();
                        move |bin, args| bin == data.bin && args == data.args
                    })
                    .times(1)
                    .returning(|_, _| Box::pin(async { Ok(()) }));
                let runner = DefaultHelmRunner {
                    bin: data.bin.into(),
                    runner,
                };
                runner
                    .upgrade(
                        data.namespace,
                        data.release,
                        data.chart,
                        data.values_filepath,
                        data.version,
                    )
                    .await
                    .unwrap();
            }

            #[tokio::test]
            async fn no_version() {
                let data = Data::default();
                test(data).await;
            }

            #[tokio::test]
            async fn version() {
                let version = "version";
                let mut data = Data {
                    version: Some(version),
                    ..Default::default()
                };
                data.args = vec![
                    "upgrade".into(),
                    "--install".into(),
                    "--create-namespace".into(),
                    "-n".into(),
                    data.namespace.into(),
                    "--values".into(),
                    data.values_filepath.to_str().unwrap().into(),
                    "--version".into(),
                    version.into(),
                    data.release.into(),
                    data.chart.into(),
                ];
                test(data).await;
            }
        }

        mod uninstall {
            use super::*;

            // Data

            #[derive(Clone)]
            struct Data {
                bin: &'static str,
                namespace: &'static str,
                release: &'static str,
            }

            impl Default for Data {
                fn default() -> Self {
                    Self {
                        bin: "helm",
                        namespace: "ns",
                        release: "release",
                    }
                }
            }

            // Tests

            #[tokio::test]
            async fn test() {
                init_tracer();
                let data = Data::default();
                let mut runner = MockCommandRunner::new();
                runner
                    .expect_run()
                    .withf({
                        let data = data.clone();
                        move |bin, args| {
                            bin == data.bin
                                && args[0] == "uninstall"
                                && args[1] == "--ignore-not-found"
                                && args[2] == "-n"
                                && args[3] == data.namespace
                                && args[4] == data.release
                        }
                    })
                    .returning(|_, _| Box::pin(async { Ok(()) }));
                let runner = DefaultHelmRunner {
                    bin: data.bin.into(),
                    runner,
                };
                runner
                    .uninstall(data.namespace, data.release)
                    .await
                    .unwrap();
            }
        }
    }
}
