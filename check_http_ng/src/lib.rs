use std::str::FromStr;

use anyhow::Context;
use clap::Parser;
use nagiosplugin::ServiceState;
use regex::Regex;

#[derive(Parser, Debug)]
#[clap(about, version)]
pub struct Opts {
    /// The backend to use for the request. Available backends: reqwest, curl
    #[clap(long, default_value = "reqwest")]
    pub backend: Backend,

    /// The URL to check
    #[clap(long = "url")]
    pub url: String,

    /// Accept invalid certificates
    #[clap(long = "accept-invalid-certs")]
    pub accept_invalid_certs: bool,

    /// The user for basic authentication
    #[clap(long = "basic-auth-user")]
    pub basic_auth_user: Option<String>,

    /// The password for basic authentication
    #[clap(long = "basic-auth-pass")]
    pub basic_auth_pass: Option<String>,

    /// If defined, the request will be proxied through the given proxy
    #[clap(long)]
    pub proxy: Option<String>,

    /// Proxy basic authentication user
    #[clap(long)]
    pub proxy_basic_user: Option<String>,

    /// Proxy basic authentication password
    #[clap(long)]
    pub proxy_basic_pass: Option<String>,

    /// The maximum time the request is allowed to take
    #[clap(long = "timeout", default_value = "60s")]
    pub timeout: Duration,

    /// The warning timeout
    #[clap(long = "timeout-warning", default_value = "15s")]
    pub timeout_warning: Duration,

    /// The critical timeout
    #[clap(long = "timeout-critical", default_value = "30s")]
    pub timeout_critical: Duration,

    /// The expected HTTP status code
    #[clap(long = "expect-status", default_value = "200")]
    pub expect_status: u16,

    /// Expect the given string literal to be included in the response.
    #[clap(long = "expect-string")]
    pub expected_string: Option<String>,

    /// If defined it will be an "ok" service state if a connection error occurs. It will be the
    /// given state if no error occurs.
    #[clap(long = "on-error")]
    pub on_error: Option<ServiceState>,

    /// Expect the given regex to match against the response and set the state accordingly.
    /// Prefix the state with a '!' to reverse the match.
    /// Format: <state>:<regex>
    #[clap(long = "regex-match")]
    pub regex_match: Vec<RegexMatch>,

    /// CA certificate file to verify peer against. Currently only supported by curl backend.
    #[clap(long = "ca-cert")]
    pub ca_cert: Option<String>,
}

#[derive(Debug, Clone, derive_more::Deref)]
pub struct Duration(std::time::Duration);

impl std::str::FromStr for Duration {
    type Err = humanize_rs::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Duration(humanize_rs::duration::parse(s)?))
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ExpectRegexParseError {
    #[error("invalid format, expected <state>:<regex>")]
    InvalidFormat,
    #[error("failed to parse state: {0}")]
    StateParseError(#[from] nagiosplugin::ServiceStateFromStrError),
    #[error("failed to parse regex: {0}")]
    RegexParseError(#[from] regex::Error),
}

#[derive(Debug, Clone)]
pub struct RegexMatch {
    pub reverse: bool,
    pub state: ServiceState,
    pub regex: Regex,
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

#[derive(Debug, Clone)]
pub enum Backend {
    Reqwest,
    Curl,
}

#[derive(thiserror::Error, Debug)]
pub enum BackendParseError {
    #[error("invalid backend: {0}")]
    InvalidBackend(String),
}

impl std::str::FromStr for Backend {
    type Err = BackendParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "reqwest" => Ok(Backend::Reqwest),
            "curl" => Ok(Backend::Curl),
            _ => Err(BackendParseError::InvalidBackend(s.to_string())),
        }
    }
}

pub type BackendResult = Result<BackendData, BackendFetchError>;

pub struct BackendData {
    pub status: u16,
    pub body: Vec<u8>,
    pub time: std::time::Duration,
}

#[derive(thiserror::Error, Debug)]
pub enum BackendFetchError {
    #[error("not reachable")]
    NotReachable,
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

impl Backend {
    pub async fn fetch(&self, opts: &Opts) -> Result<BackendData, BackendFetchError> {
        match self {
            Backend::Reqwest => backend_reqwest::fetch(opts).await,
            Backend::Curl => backend_curl::fetch(opts),
        }
    }
}

mod backend_curl {
    use super::*;

    #[derive(serde::Deserialize)]
    pub struct CurlOutput {
        #[serde(rename = "exitcode")]
        pub exit_code: i32,
        #[serde(rename = "errormsg")]
        pub error_message: Option<String>,
        pub http_code: u16,
        pub http_version: String,
        pub size_download: usize,
        pub size_header: usize,
        /// Seconds
        pub time_total: f32,
    }

    pub fn fetch(opts: &Opts) -> BackendResult {
        let mut cmd = std::process::Command::new("curl");
        if let Some(proxy) = &opts.proxy {
            cmd.arg("--proxy").arg(proxy);
        }

        let file = tempfile::NamedTempFile::new().context("failed to create temporary file")?;

        cmd.arg("-s")
            .arg("-w")
            .arg("%{json}")
            .arg("-o")
            .arg(file.path());

        if opts.accept_invalid_certs {
            cmd.arg("-k");
        }

        if let Some(ca_cert) = &opts.ca_cert {
            cmd.arg("--cacert").arg(ca_cert);
        }

        cmd.arg("--connect-timeout")
            .arg(format!("{:.3}", opts.timeout.as_secs_f32()));

        if let (Some(user), Some(pass)) = (&opts.basic_auth_user, &opts.basic_auth_pass) {
            cmd.arg("-u").arg(format!("{}:{}", user, pass));
        }

        if let Some(proxy) = &opts.proxy {
            cmd.arg("--proxy").arg(proxy);
        }

        if let (Some(user), Some(pass)) = (&opts.proxy_basic_user, &opts.proxy_basic_pass) {
            cmd.arg("--proxy-basic")
                .arg("--proxy-user")
                .arg(format!("{}:{}", user, pass));
        }

        cmd.arg(&opts.url);

        tracing::debug!("executing curl: {:?}", cmd);

        let output = cmd.output().context("failed to execute curl")?;

        tracing::debug!("curl stdout: {}", String::from_utf8_lossy(&output.stdout));
        tracing::debug!("curl stderr: {}", String::from_utf8_lossy(&output.stderr));

        let output = String::from_utf8_lossy(&output.stdout);
        let output: CurlOutput =
            serde_json::from_str(&output).context("failed to parse curl output")?;

        if let Some(error_message) = &output.error_message {
            if error_message.contains("Timeout was reached")
                || error_message.contains("Connection time-out")
                || error_message.contains("SSL connection timeout")
            {
                return Err(BackendFetchError::NotReachable);
            } else {
                return Err(anyhow::anyhow!("curl error: {}", error_message).into());
            }
        }

        let body =
            std::fs::read(file.path()).context("failed to read curl temporary output file")?;

        Ok(BackendData {
            status: output.http_code,
            body,
            time: std::time::Duration::from_secs_f32(output.time_total),
        })
    }
}

mod backend_reqwest {
    use super::*;

    pub async fn fetch(opts: &Opts) -> BackendResult {
        let client = {
            let mut builder = reqwest::ClientBuilder::new()
                .redirect(reqwest::redirect::Policy::none())
                .danger_accept_invalid_certs(opts.accept_invalid_certs);

            if let Some(proxy) = &opts.proxy {
                let mut proxy = reqwest::Proxy::all(proxy).context("failed to set proxy")?;

                if let (Some(user), Some(pass)) = (&opts.proxy_basic_user, &opts.proxy_basic_pass) {
                    proxy = proxy.basic_auth(&user, &pass);
                }

                builder = builder.proxy(proxy);
            }

            builder.build().context("failed to create client")?
        };

        let req = {
            let mut builder = client.get(&opts.url);
            if let Some(user) = &opts.basic_auth_user {
                builder = builder.basic_auth(user, opts.basic_auth_pass.as_ref());
            }
            builder = builder.timeout(*opts.timeout);
            builder.build().context("failed to build request")?
        };

        let start = std::time::Instant::now();
        let resp = client.execute(req).await;

        let resp = match resp {
            Ok(resp) => resp,
            Err(err) => {
                if err.is_timeout() {
                    return Err(BackendFetchError::NotReachable);
                } else {
                    return Err(BackendFetchError::Other(
                        anyhow::anyhow!(err).context("failed to execute request"),
                    ));
                }
            }
        };

        let status = resp.status().as_u16();
        let body = resp.bytes().await.context("failed to read body")?.to_vec();
        let time = start.elapsed();

        Ok(BackendData { status, body, time })
    }
}
