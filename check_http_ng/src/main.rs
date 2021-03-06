use std::error::Error;

use nagiosplugin::{CheckResult, Metric, Resource, ServiceState, TriggerIfValue};
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(author)]
struct Opts {
    #[structopt(short = "u", long = "url")]
    url: String,

    #[structopt(short = "w", long = "warning-timeout", default_value = "15000")]
    warning: u64,

    #[structopt(short = "c", long = "critical-timeout", default_value = "30000")]
    critical: u64,

    #[structopt(short = "s", long = "expect-status", default_value = "200")]
    status: u16,

    #[structopt(long = "accept-invalid-certs")]
    accept_invalid_certs: bool,

    #[structopt(long = "basic-auth-user")]
    basic_auth_user: Option<String>,

    #[structopt(long = "basic-auth-pass")]
    basic_auth_pass: Option<String>,

    /// Expect the given string literal to be included in the response.
    #[structopt(long = "expect-string")]
    expected_string: Option<String>,

    /// If defined it will be an "ok" service state if a connection error occurs. It will be the
    /// given state if no error occurs.
    #[structopt(long = "expect-error")]
    expect_error: Option<ServiceState>,
}

fn main() {
    let opts: Opts = Opts::from_args();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    nagiosplugin::Runner::new()
        .safe_run(|| rt.block_on(check_http_ng(opts)))
        .print_and_exit();
}

async fn check_http_ng(opts: Opts) -> Result<Resource, Box<dyn Error>> {
    let mut res = Resource::new("HTTP");

    let client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(opts.accept_invalid_certs)
        .build()?;
    let start = chrono::Utc::now();

    let mut req_builder = client.get(&opts.url);
    if let Some(user) = opts.basic_auth_user {
        req_builder = req_builder.basic_auth(user, opts.basic_auth_pass);
    }

    let resp = match client.execute(req_builder.build()?).await {
        Ok(r) => match opts.expect_error {
            Some(state) => {
                res.push_result(
                    CheckResult::new()
                        .with_state(state)
                        .with_message("expected service to be errorneous, but it is not"),
                );
                r
            }
            None => r,
        },
        Err(e) => match opts.expect_error {
            Some(_) => {
                return Ok(res
                    .with_fixed_state(ServiceState::Ok)
                    .with_description("Expected service to be errorneous and it is"));
            }
            None => {
                Err(e)?;
                unreachable!()
            }
        },
    };

    let status = resp.status().as_u16();
    let bytes = resp.bytes().await?;

    if let Some(ref expected_string) = opts.expected_string {
        let response_body = String::from_utf8_lossy(bytes.as_ref());
        if !response_body.contains(expected_string) {
            res.push_result(
                CheckResult::new()
                    .with_state(ServiceState::Critical)
                    .with_message(format!("Unable to find string \"{}\"", expected_string)),
            );
        }
    }

    let byte_count = bytes.len();
    res.push_result(Metric::new("size", byte_count));

    let end = chrono::Utc::now();
    let took = end - start;

    res.push_result(
        Metric::new("time", took.num_milliseconds() as u64)
            .with_thresholds(opts.warning, opts.critical, TriggerIfValue::Greater)
            .with_minimum(0),
    );

    if status != opts.status {
        res.push_result(
            CheckResult::new()
                .with_state(ServiceState::Critical)
                .with_message(format!(
                    "expected status code {} but got {}",
                    opts.status, status
                )),
        );
    };

    res.set_description(format!(
        "Status Code {} - Received {} bytes in {} milliseconds",
        status,
        byte_count,
        took.num_milliseconds()
    ));

    Ok(res)
}
