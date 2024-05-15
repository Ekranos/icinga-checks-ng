use anyhow::Context;
use chrono::{Local, NaiveDateTime};
use clap::Parser;
use nagiosplugin::{safe_run, CheckResult, Metric, Resource, ServiceState, TriggerIfValue};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Parser)]
struct Opts {
    /// The address to connect to. Example: example.com:443
    #[clap(long)]
    address: String,

    /// The domain to request the certificate from. Example: example.com
    #[clap(long)]
    domain: String,

    /// Time in days until expiry to report a warning
    #[clap(long, default_value = "30")]
    warning: u64,

    /// Time in days until expiry to report a critical
    #[clap(long, default_value = "14")]
    critical: u64,

    /// Service state to emit if the certificate is not valid yet
    #[clap(long, default_value = "critical")]
    not_before_state: ServiceState,

    /// If set, the check will expect the address to not respond and will issue the given state if it does respond
    #[clap(long)]
    expect_error: Option<ServiceState>,

    /// The timeout in milliseconds
    #[clap(long, default_value = "15000")]
    timeout: u64,
}

struct CertificateInfo {
    issuer: String,
    subject: String,
    not_before: NaiveDateTime,
    not_after: NaiveDateTime,
}

fn main() {
    let opts = Opts::parse();

    safe_run(|| do_check(&opts), ServiceState::Unknown).print_and_exit();
}

fn do_check(opts: &Opts) -> anyhow::Result<Resource> {
    let mut resource = Resource::new("SSL");

    let certs: Arc<Mutex<Vec<CertificateInfo>>> = Default::default();
    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    let inner_certs = certs.clone();
    builder.set_verify_callback(SslVerifyMode::NONE, move |_, cert| {
        let current = cert.current_cert().unwrap();

        let info = CertificateInfo {
            issuer: current
                .issuer_name()
                .entries()
                .map(|e| e.data().as_utf8().unwrap().to_string())
                .collect::<Vec<_>>()
                .join(", "),
            subject: current
                .subject_name()
                .entries()
                .map(|e| e.data().as_utf8().unwrap().to_string())
                .collect::<Vec<_>>()
                .join(", "),
            not_before: NaiveDateTime::parse_from_str(
                &current.not_before().to_string(),
                "%b %e %T %Y %Z",
            )
            .unwrap(),
            not_after: NaiveDateTime::parse_from_str(
                &current.not_after().to_string(),
                "%b %e %T %Y %Z",
            )
            .unwrap(),
        };
        let mut certs = inner_certs.lock().unwrap();
        certs.push(info);
        true
    });

    let connector = builder.build();

    let addr = opts
        .address
        .to_socket_addrs()
        .with_context(|| "invalid address")?
        .next()
        .with_context(|| "no address found")?;

    let stream = TcpStream::connect_timeout(&addr, Duration::from_millis(opts.timeout))
        .with_context(|| format!("error connecting to {}", &opts.address));

    let stream = match (stream, opts.expect_error) {
        (Ok(_), Some(state)) => {
            resource.set_description("Expected remote to be unreachable, but it is reachable.");
            resource = resource.with_fixed_state(state);
            return Ok(resource);
        }
        (Ok(stream), None) => stream,
        (Err(_), Some(_)) => {
            resource.set_description("Expected remote to be unreachable and it is.");
            resource = resource.with_fixed_state(ServiceState::Ok);
            return Ok(resource);
        }
        (Err(e), None) => return Err(e),
    };
    connector
        .connect(&opts.domain, stream)
        .with_context(|| "error creating ssl connection")?;

    let certs = certs.lock().unwrap();
    let last_cert = certs.last().with_context(|| "no certificates received")?;

    resource.set_description(format!(
        "Certificate with subject '{}' signed by '{}' expires at {}",
        &last_cert.subject,
        &last_cert.issuer,
        last_cert.not_after.format("%c")
    ));

    let now = Local::now().naive_local();
    {
        let left_days = (last_cert.not_after - now).num_days() as u64;
        resource.push_result(Metric::new("not_after", left_days).with_thresholds(
            opts.warning,
            opts.critical,
            TriggerIfValue::Less,
        ));
    }

    {
        let days_until = (last_cert.not_before - now).num_days();
        if days_until > 0 {
            resource.push_result(
                CheckResult::new()
                    .with_state(opts.not_before_state)
                    .with_message(format!(
                        "Certificate is not valid yet. It's valid at {}",
                        last_cert.not_before.format("%c")
                    )),
            )
        }
    }

    Ok(resource)
}
