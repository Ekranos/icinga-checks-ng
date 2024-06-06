use anyhow::Context;
use chrono::{Local, NaiveDateTime};
use clap::Parser;
use nagiosplugin::{safe_run, CheckResult, Metric, Resource, ServiceState, TriggerIfValue};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::X509;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(clap::Args)]
struct CommonOpts {
    /// Time in days until expiry to report a warning
    #[clap(long, global = true, default_value = "30")]
    warning: u64,

    /// Time in days until expiry to report a critical
    #[clap(long, global = true, default_value = "14")]
    critical: u64,

    /// Service state to emit if the certificate is not valid yet
    #[clap(long, global = true, default_value = "critical")]
    not_before_state: ServiceState,

    /// If set, the check will expect the address to not respond and will issue the given state if it does respond
    #[clap(long, global = true)]
    expect_error: Option<ServiceState>,
}

#[derive(clap::Args)]
struct HttpOpts {
    /// The address to connect to. Example: example.com:443
    #[clap(long)]
    address: String,

    /// The domain to request the certificate from. Example: example.com
    #[clap(long)]
    domain: String,

    /// The timeout in milliseconds
    #[clap(long, default_value = "15000")]
    timeout: u64,
}

#[derive(clap::Args)]
struct FileOpts {
    /// The path to the certificate file
    #[clap(long)]
    path: PathBuf,
}

#[derive(clap::Parser)]
struct Cli {
    #[clap(flatten)]
    common: CommonOpts,

    #[clap(subcommand)]
    subcommand: SubCommand,
}

#[derive(clap::Subcommand)]
enum SubCommand {
    /// Fetch a certificate from a remote server via TLS handshake
    Http(HttpOpts),
    /// Read a certificate from a file
    File(FileOpts),
}

struct CertificateInfo {
    issuer: String,
    subject: String,
    not_before: NaiveDateTime,
    not_after: NaiveDateTime,
}

fn main() {
    let cli = Cli::parse();

    safe_run(|| do_check(&cli), ServiceState::Unknown).print_and_exit();
}

fn do_check(cli: &Cli) -> anyhow::Result<Resource> {
    let mut resource = Resource::new("SSL");

    let cert = match &cli.subcommand {
        SubCommand::Http(opts) => match (fetch_cert(opts), cli.common.expect_error) {
            (Ok(_), Some(state)) => {
                resource.set_description("Expected remote to be unreachable, but it is reachable.");
                resource = resource.with_fixed_state(state);
                return Ok(resource);
            }
            (Ok(cert), None) => cert,
            (Err(_), Some(_)) => {
                resource.set_description("Expected remote to be unreachable and it is.");
                resource = resource.with_fixed_state(ServiceState::Ok);
                return Ok(resource);
            }
            (Err(e), None) => Err(e)?,
        },
        SubCommand::File(opts) => read_cert(opts)?,
    };

    let cert = to_certificate_info(&cert);

    resource.set_description(format!(
        "Certificate with subject '{}' signed by '{}' expires at {}",
        &cert.subject,
        &cert.issuer,
        cert.not_after.format("%c")
    ));

    let now = Local::now().naive_local();
    {
        let left_days = (cert.not_after - now).num_days() as u64;
        resource.push_result(Metric::new("not_after", left_days).with_thresholds(
            cli.common.warning,
            cli.common.critical,
            TriggerIfValue::Less,
        ));
    }

    {
        let days_until = (cert.not_before - now).num_days();
        if days_until > 0 {
            resource.push_result(
                CheckResult::new()
                    .with_state(cli.common.not_before_state)
                    .with_message(format!(
                        "Certificate is not valid yet. It's valid at {}",
                        cert.not_before.format("%c")
                    )),
            )
        }
    }

    Ok(resource)
}

#[derive(Debug, thiserror::Error)]
enum FetchCertError {
    #[error("connection error: {0}")]
    ConnectError(#[from] std::io::Error),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

fn fetch_cert(opts: &HttpOpts) -> Result<X509, FetchCertError> {
    let certs: Arc<Mutex<Vec<X509>>> = Default::default();
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    let inner_certs = certs.clone();
    builder.set_verify_callback(SslVerifyMode::NONE, move |_, cert| {
        let current = cert.current_cert().unwrap();

        let mut certs = inner_certs.lock().unwrap();
        certs.push(current.to_owned());
        true
    });

    let connector = builder.build();

    let addr = opts
        .address
        .to_socket_addrs()
        .with_context(|| "invalid address")?
        .next()
        .with_context(|| "no address found")?;

    let stream = TcpStream::connect_timeout(&addr, Duration::from_millis(opts.timeout))?;

    connector
        .connect(&opts.domain, stream)
        .with_context(|| "error creating ssl connection")?;

    let certs = certs.lock().unwrap();
    let last_cert = certs.last().with_context(|| "no certificates received")?;

    Ok(last_cert.clone())
}

fn read_cert(opts: &FileOpts) -> anyhow::Result<X509> {
    let content = std::fs::read(&opts.path).context("failed to read certificate file")?;

    if let Ok(cert) = X509::from_der(&content) {
        return Ok(cert);
    }

    if let Ok(cert) = X509::from_pem(&content) {
        return Ok(cert);
    }

    Err(anyhow::anyhow!("failed to parse certificate"))
}

fn to_certificate_info(cert: &X509) -> CertificateInfo {
    CertificateInfo {
        issuer: cert
            .issuer_name()
            .entries()
            .map(|e| e.data().as_utf8().unwrap().to_string())
            .collect::<Vec<_>>()
            .join(", "),
        subject: cert
            .subject_name()
            .entries()
            .map(|e| e.data().as_utf8().unwrap().to_string())
            .collect::<Vec<_>>()
            .join(", "),
        not_before: NaiveDateTime::parse_from_str(&cert.not_before().to_string(), "%b %e %T %Y %Z")
            .unwrap(),
        not_after: NaiveDateTime::parse_from_str(&cert.not_after().to_string(), "%b %e %T %Y %Z")
            .unwrap(),
    }
}
