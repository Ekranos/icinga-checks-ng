use std::str::FromStr;

use anyhow::Context;
use clap::Parser;
use nagiosplugin::{safe_run, CheckResult, Metric, Resource, ServiceState, TriggerIfValue};
use regex::Regex;

#[derive(Parser, Debug)]
#[clap(about, version)]
struct Opts {
    #[clap(short = 'u', long = "url")]
    url: String,

    #[clap(short = 'w', long = "warning-timeout", default_value = "15000")]
    warning: u64,

    #[clap(short = 'c', long = "critical-timeout", default_value = "30000")]
    critical: u64,

    #[clap(short = 's', long = "expect-status", default_value = "200")]
    status: u16,

    #[clap(long = "accept-invalid-certs")]
    accept_invalid_certs: bool,

    #[clap(long = "basic-auth-user")]
    basic_auth_user: Option<String>,

    #[clap(long = "basic-auth-pass")]
    basic_auth_pass: Option<String>,

    /// Expect the given string literal to be included in the response.
    #[clap(long = "expect-string")]
    expected_string: Option<String>,

    /// If defined it will be an "ok" service state if a connection error occurs. It will be the
    /// given state if no error occurs.
    #[clap(long = "expect-error")]
    expect_error: Option<ServiceState>,

    /// Expect the given regex to match against the response and set the state accordingly.
    /// Prefix the state with a '!' to reverse the match.
    /// Format: <state>:<regex>
    #[clap(long = "regex-match")]
    regex_match: Vec<RegexMatch>,

    /// If defined, the request will be proxied through the given URL.
    #[clap(long)]
    proxy: Option<String>,

    /// Proxy http authentication user
    #[clap(long)]
    proxy_user: Option<String>,

    /// Proxy http authentication password
    #[clap(long)]
    proxy_pass: Option<String>,
}

#[derive(thiserror::Error, Debug)]
enum ExpectRegexParseError {
    #[error("invalid format, expected <state>:<regex>")]
    InvalidFormat,
    #[error("failed to parse state: {0}")]
    StateParseError(#[from] nagiosplugin::ServiceStateFromStrError),
    #[error("failed to parse regex: {0}")]
    RegexParseError(#[from] regex::Error),
}

#[derive(Debug, Clone)]
struct RegexMatch {
    reverse: bool,
    state: ServiceState,
    regex: Regex,
}

impl FromStr for RegexMatch {
    type Err = ExpectRegexParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (state, regex) = s
            .split_once(':')
            .ok_or(ExpectRegexParseError::InvalidFormat)?;

        let (state, reverse) = if state.starts_with('!') {
            (&state[1..], true)
        } else {
            (state, false)
        };

        let state = state.parse()?;
        let regex = Regex::new(regex)?;

        Ok(RegexMatch {
            reverse,
            state,
            regex,
        })
    }
}

fn main() {
    let opts: Opts = Opts::parse();
    tracing_subscriber::fmt::init();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    safe_run(|| rt.block_on(check_http_ng(opts)), ServiceState::Unknown).print_and_exit();
}

async fn check_http_ng(opts: Opts) -> anyhow::Result<Resource> {
    let mut res = Resource::new("HTTP");

    let client = {
        let mut builder = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(opts.accept_invalid_certs);

        if let Some(proxy) = opts.proxy {
            let mut proxy = reqwest::Proxy::all(proxy).context("failed to set proxy")?;

            if let (Some(user), Some(pass)) = (opts.proxy_user, opts.proxy_pass) {
                proxy = proxy.basic_auth(&user, &pass);
            }

            builder = builder.proxy(proxy);
        }

        builder.build().context("failed to create client")?
    };

    let start = std::time::Instant::now();

    let req = {
        let mut builder = client.get(&opts.url);
        if let Some(user) = opts.basic_auth_user {
            builder = builder.basic_auth(user, opts.basic_auth_pass);
        }
        builder.build().context("failed to build request")?
    };

    let resp = match client.execute(req).await {
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
            None => anyhow::bail!("failed to execute request: {}", e),
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

    for regex_match in &opts.regex_match {
        let response_body = String::from_utf8_lossy(bytes.as_ref());
        if regex_match.regex.is_match(&response_body) && !regex_match.reverse {
            res.push_result(
                CheckResult::new()
                    .with_state(regex_match.state)
                    .with_message(format!(
                        "regex '{}' matches body for state '{}'",
                        regex_match.regex, regex_match.state
                    )),
            );
        }
    }

    let byte_count = bytes.len();
    res.push_result(Metric::new("size", byte_count));

    let elapsed = start.elapsed();

    res.push_result(
        Metric::new("time", elapsed.as_millis() as u64)
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
        "Status Code {} - Received {} bytes in {:?}",
        status, byte_count, elapsed
    ));

    Ok(res)
}
