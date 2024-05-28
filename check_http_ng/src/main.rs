use anyhow::Context;
use check_http_ng::{BackendFetchError, BackendResult, Opts};
use clap::Parser;
use nagiosplugin::{safe_run, CheckResult, Metric, Resource, ServiceState, TriggerIfValue};

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
    let mut resource = Resource::new("HTTP");

    let res = opts.backend.fetch(&opts).await;

    if matches!(res, BackendResult::Err(BackendFetchError::NotReachable)) {
        match opts.on_error {
            Some(state) => {
                return Ok(resource.with_fixed_state(state).with_description(format!(
                    "Unreachable. Overriding state to {} based on parameter",
                    state
                )))
            }
            None => {
                return Ok(resource
                    .with_fixed_state(ServiceState::Critical)
                    .with_description("Unreachable"))
            }
        }
    }

    let res = res.context("Failed to fetch URL")?;

    if let Some(ref expected_string) = opts.expected_string {
        let response_body = String::from_utf8_lossy(&res.body);
        if !response_body.contains(expected_string) {
            resource.push_result(
                CheckResult::new()
                    .with_state(ServiceState::Critical)
                    .with_message(format!("Unable to find string \"{}\"", expected_string)),
            );
        }
    }

    for regex_match in &opts.regex_match {
        let response_body = String::from_utf8_lossy(&res.body);
        if regex_match.regex.is_match(&response_body) && !regex_match.reverse {
            resource.push_result(
                CheckResult::new()
                    .with_state(regex_match.state)
                    .with_message(format!(
                        "regex '{}' matches body for state '{}'",
                        regex_match.regex, regex_match.state
                    )),
            );
        }
    }

    resource.push_result(Metric::new("size", res.body.len()));

    resource.push_result(
        Metric::new("time", res.time.as_millis() as u64)
            .with_thresholds(
                (*opts.timeout_warning).as_millis() as u64,
                (*opts.timeout_critical).as_millis() as u64,
                TriggerIfValue::Greater,
            )
            .with_minimum(0),
    );

    if res.status != opts.expect_status {
        resource.push_result(
            CheckResult::new()
                .with_state(ServiceState::Critical)
                .with_message(format!(
                    "expected status code {} but got {}",
                    opts.expect_status, res.status
                )),
        );
    };

    resource.set_description(format!(
        "Status Code {} - Received {} bytes in {:?}",
        res.status,
        res.body.len(),
        res.time
    ));

    Ok(resource)
}
