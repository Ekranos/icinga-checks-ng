use std::error::Error;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::str::FromStr;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context};
use nagiosplugin::{CheckResult, Metric, Resource, ServiceState, TriggerIfValue};
use structopt::StructOpt;
use trust_dns_client::client::{Client, ClientConnection, SyncClient};
use trust_dns_client::op::DnsResponse;
use trust_dns_client::rr::{DNSClass, Name, RecordType};
use trust_dns_client::tcp::TcpClientConnection;
use trust_dns_client::udp::UdpClientConnection;

#[derive(Debug, Copy, Clone)]
enum ConnectionType {
    Tcp,
    Udp,
}

impl FromStr for ConnectionType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tcp" => Ok(ConnectionType::Tcp),
            "udp" => Ok(ConnectionType::Udp),
            _ => Err(anyhow!("expected 'tcp' or 'udp'")),
        }
    }
}

trait DnsClient {
    fn query(
        &self,
        name: &Name,
        dns_class: DNSClass,
        record_type: RecordType,
    ) -> Result<DnsResponse, anyhow::Error>;
}

struct DnsClientWrapper<CC: ClientConnection> {
    client: SyncClient<CC>,
}

impl<CC: ClientConnection> DnsClient for DnsClientWrapper<CC> {
    fn query(
        &self,
        name: &Name,
        dns_class: DNSClass,
        record_type: RecordType,
    ) -> Result<DnsResponse, anyhow::Error> {
        Ok(self.client.query(name, dns_class, record_type)?)
    }
}

fn create_client(
    typ: ConnectionType,
    addr: SocketAddr,
    timeout: Duration,
) -> Result<Box<dyn DnsClient>, anyhow::Error> {
    match typ {
        ConnectionType::Tcp => Ok(Box::new(DnsClientWrapper {
            client: SyncClient::new(TcpClientConnection::with_timeout(addr, timeout)?),
        })),
        ConnectionType::Udp => Ok(Box::new(DnsClientWrapper {
            client: SyncClient::new(UdpClientConnection::with_timeout(addr, timeout)?),
        })),
    }
}

/// Easier and more flexible Nagios/Icinga compatible DNS check plugin.
/// Built cause of the lack of reliably choosing between TCP and UDP for the connection
/// by check_dns and check_dig.
#[derive(Debug, Clone, StructOpt)]
#[structopt(author)]
struct Opts {
    /// The DNS server to use
    #[structopt(short, default_value = "127.0.0.1:53")]
    server_address: SocketAddr,
    /// The name to resolve
    #[structopt(short)]
    hostname: Name,
    /// Choose how to connect to the DNS server (tcp, udp)
    #[structopt(short = "t", default_value = "udp")]
    connection_type: ConnectionType,
    /// The expected response string. Example: 1.2.3.4,1.2.3.5
    /// The received answers will be sorted lexically before comparing to the given string
    #[structopt(short)]
    expected_response: Option<String>,
    /// Warn if the response time is over the given value
    #[structopt(short, default_value = "2500")]
    warning: NonZeroU32,
    /// Critical if the response time is over the given value
    #[structopt(short, default_value = "5000")]
    critical: NonZeroU32,
    /// Which dns class to check (IN, ANY, CH, HS, NONE)
    #[structopt(long, default_value = "IN")]
    dns_class: DNSClass,
    /// Which record type to query (A, AAAA, CNAME etc.)
    #[structopt(long, default_value = "A")]
    record_type: RecordType,
    /// Timeout in milliseconds
    #[structopt(long = "timeout", default_value = "10000")]
    timeout_milliseconds: NonZeroU32,
}

fn main() {
    let opts: Opts = Opts::from_args();

    nagiosplugin::Runner::new()
        .safe_run(|| check_dns_ng(opts))
        .print_and_exit();
}

fn check_dns_ng(opts: Opts) -> Result<Resource, Box<dyn Error>> {
    let mut resource = Resource::new("DNS");

    let start = Instant::now();

    let timeout = Duration::from_millis(opts.timeout_milliseconds.get() as u64);
    let client = create_client(opts.connection_type, opts.server_address, timeout)
        .with_context(|| "unable to create client")?;

    let response = client
        .query(&opts.hostname, opts.dns_class, opts.record_type)
        .with_context(|| "query failed")?;

    let duration = Instant::now() - start;

    resource.push_result(
        Metric::new("response_time", duration.as_millis() as u32)
            .with_thresholds(
                opts.warning.get(),
                opts.critical.get(),
                TriggerIfValue::Greater,
            )
            .with_minimum(0),
    );

    let answers = response.answers();
    resource.push_result(Metric::new("answers", answers.len()));

    let mut ips = answers
        .iter()
        .map(|a| a.rdata().to_string())
        .collect::<Vec<_>>();

    ips.sort();
    let ips = ips.join(",");

    resource.set_description(format!(
        "Received answer '{}' in {}ms",
        ips,
        duration.as_millis()
    ));

    if let Some(expected) = opts.expected_response {
        if expected != ips {
            resource.push_result(
                CheckResult::new()
                    .with_message(format!(
                        "expected response '{}' but got '{}'",
                        &expected, &ips
                    ))
                    .with_state(ServiceState::Critical),
            );
        }
    }

    Ok(resource)
}
