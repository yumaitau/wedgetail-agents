//! `wedgetail-agent`: collect host logs and ship them to Wedgetail.

// Only the Windows service glue under `os/` may contain `unsafe` (from a macro expansion).
#![deny(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use agent_config::AgentConfig;
use agent_core::telemetry::{AGENT_VERSION, STATUS_FILE};
use agent_core::{Agent, FileCredential, Stop};
use serde_json::Value;

mod logger;
#[cfg(windows)]
#[allow(unsafe_code)]
mod os;

const USAGE: &str = "\
Usage: wedgetail-agent <command> [options]

Commands:
  run            Run the agent in the foreground (the service manager runs this)
  enrol          Enrol this host with Wedgetail
  check-config   Validate agent.toml and rules.d, then exit
  status         Show the running agent's last status
  version        Print the version

Options:
  --config <path>  agent.toml location (default: the OS default path)
  --json           status: print the raw status JSON
  --service        run: run as a Windows service (set by the service installer)

Environment:
  WEDGETAIL_LOG    error, warn, info (default) or debug
";

#[derive(Debug, Default)]
struct Args {
    command: String,
    config: Option<PathBuf>,
    json: bool,
    service: bool,
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut parsed = Args::default();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => parsed.config = Some(args.next().ok_or("--config needs a path")?.into()),
            "--json" => parsed.json = true,
            "--service" => parsed.service = true,
            "-h" | "--help" | "help" => parsed.command = "help".into(),
            "-V" | "--version" => parsed.command = "version".into(),
            flag if flag.starts_with('-') => return Err(format!("unknown option {flag}")),
            command if parsed.command.is_empty() => parsed.command = command.to_owned(),
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }
    Ok(parsed)
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(e) => return fail(&format!("{e}\n\n{USAGE}")),
    };
    let config_path = args
        .config
        .clone()
        .unwrap_or_else(agent_config::paths::default_config_path);
    let result = match args.command.as_str() {
        "run" if args.service => run_service(config_path),
        "run" => {
            logger::init_stderr();
            run(&config_path)
        }
        "enrol" | "enroll" => Err(
            "enrolment is not available in this build yet. It will read the enrolment token \
             from stdin or WEDGETAIL_ENROL_TOKEN, never from the command line."
                .into(),
        ),
        "check-config" => check_config(&config_path),
        "status" => status(&config_path, args.json),
        "version" => {
            out(&format!(
                "wedgetail-agent {AGENT_VERSION} ({} {})",
                std::env::consts::OS,
                std::env::consts::ARCH
            ));
            Ok(())
        }
        "help" => {
            out(USAGE);
            Ok(())
        }
        "" => Err(USAGE.trim_end().to_owned()),
        other => Err(format!("unknown command {other:?}\n\n{USAGE}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(&e),
    }
}

#[allow(clippy::print_stdout)]
fn out(text: &str) {
    println!("{text}");
}

#[allow(clippy::print_stderr)]
fn fail(message: &str) -> ExitCode {
    eprintln!("wedgetail-agent: {message}");
    ExitCode::FAILURE
}

fn load(config_path: &Path) -> Result<AgentConfig, String> {
    AgentConfig::load(config_path).map_err(|e| e.to_string())
}

/// Build the agent for a loaded config. Shared by `run` and the Windows service.
fn build_agent(config: AgentConfig) -> Result<Agent, String> {
    // Enrolment (a later release) replaces this with OS secure storage; the file is the Linux
    // layout and works everywhere in the meantime.
    let credential = Arc::new(FileCredential {
        path: config.state_dir.join("credential"),
    });
    Agent::new(config, credential).map_err(|e| e.to_string())
}

fn run(config_path: &Path) -> Result<(), String> {
    let agent = build_agent(load(config_path)?)?;
    let stop = Stop::new();
    let handler_stop = stop.clone();
    ctrlc::set_handler(move || {
        log::info!("stop requested");
        handler_stop.stop();
    })
    .map_err(|e| format!("cannot install the signal handler: {e}"))?;
    agent.run(stop).map_err(|e| e.to_string())
}

#[cfg(windows)]
fn run_service(config_path: PathBuf) -> Result<(), String> {
    os::windows::service::run(config_path)
}

#[cfg(not(windows))]
fn run_service(_config_path: PathBuf) -> Result<(), String> {
    Err("--service is only for Windows; use systemd or launchd elsewhere".into())
}

fn check_config(config_path: &Path) -> Result<(), String> {
    let config = load(config_path)?;
    // Building the agent checks every rule type is supported on this OS.
    build_agent(config.clone())?;
    let enabled = config.rules.iter().filter(|r| r.enabled).count();
    out(&format!(
        "{}: OK\n  endpoint: {}\n  state_dir: {}\n  buffer: {} MiB\n  rules: {enabled} enabled, {} disabled",
        config_path.display(),
        config.endpoint_base(),
        config.state_dir.display(),
        config.buffer.max_mb,
        config.rules.len() - enabled,
    ));
    for rule in &config.rules {
        let disabled = if rule.enabled { "" } else { " disabled" };
        out(&format!(
            "    {} ({:?}, {}){disabled}",
            rule.id,
            rule.kind,
            rule.source_type()
        ));
    }
    Ok(())
}

fn status(config_path: &Path, json: bool) -> Result<(), String> {
    let state_dir = match AgentConfig::load(config_path) {
        Ok(config) => config.state_dir,
        Err(_) => agent_config::paths::default_state_dir(),
    };
    let path = state_dir.join(STATUS_FILE);
    let text = std::fs::read_to_string(&path).map_err(|e| {
        format!(
            "cannot read {} ({e}); is the agent running, and are you root or an administrator?",
            path.display()
        )
    })?;
    if json {
        out(text.trim_end());
        return Ok(());
    }
    let s: Value = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    out(&format_status(&s));
    Ok(())
}

fn format_status(s: &Value) -> String {
    let text = |v: &Value| match v {
        Value::String(s) => s.clone(),
        Value::Null => "-".to_owned(),
        other => other.to_string(),
    };
    let mut lines = vec![
        format!(
            "agent:       {} (pid {})",
            text(&s["agent_version"]),
            text(&s["pid"])
        ),
        format!("updated:     {}", text(&s["updated"])),
        format!("uptime:      {} s", text(&s["uptime_s"])),
        format!(
            "host:        {} ({}, {})",
            text(&s["hostname"]),
            text(&s["os"]),
            text(&s["os_version"])
        ),
        format!(
            "buffer:      {} events, {} bytes",
            text(&s["buffer_events"]),
            text(&s["buffer_bytes"])
        ),
        format!(
            "dropped:     buffer_full {}, oversize {}, sampled {}, rate_limited {}",
            text(&s["dropped"]["buffer_full"]),
            text(&s["dropped"]["oversize"]),
            text(&s["dropped"]["sampled"]),
            text(&s["dropped"]["rate_limited"])
        ),
        format!(
            "sent:        {} events in {} batches",
            text(&s["sent_events"]),
            text(&s["sent_batches"])
        ),
        format!("last sent:   {}", text(&s["ship"]["last_success"])),
        format!("last error:  {}", text(&s["ship"]["last_error"])),
        "collectors:".to_owned(),
    ];
    for c in s["collectors"].as_array().into_iter().flatten() {
        let err = c
            .get("last_error")
            .map(|e| format!(" last error: {}", text(e)))
            .unwrap_or_default();
        lines.push(format!(
            "  {:<24} {:<8} errors {}{err}",
            text(&c["rule_id"]),
            text(&c["state"]),
            text(&c["errors"])
        ));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Result<Args, String> {
        parse_args(list.iter().map(|s| (*s).to_owned()))
    }

    #[test]
    fn parses_commands_and_options() {
        let a = args(&["run", "--config", "/etc/x.toml"]).expect("ok");
        assert_eq!(a.command, "run");
        assert_eq!(a.config, Some(PathBuf::from("/etc/x.toml")));
        assert!(args(&["status", "--json"]).expect("ok").json);
        assert!(args(&["run", "--service"]).expect("ok").service);
        assert_eq!(args(&["--version"]).expect("ok").command, "version");
        assert!(args(&["run", "--config"]).is_err());
        assert!(args(&["run", "--insecure"]).is_err());
        assert!(args(&["run", "extra"]).is_err());
    }

    #[test]
    fn status_text() {
        let s = serde_json::json!({
            "agent_version": "0.1.0", "pid": 42, "uptime_s": 61, "hostname": "web-01", "os": "linux",
            "os_version": "Ubuntu 24.04", "buffer_events": 3, "buffer_bytes": 300,
            "dropped": {"buffer_full": 0, "oversize": 1, "sampled": 0, "rate_limited": 0},
            "sent_events": 10, "sent_batches": 2, "ship": {"last_success": null, "last_error": "HTTP 503"},
            "collectors": [{"rule_id": "ssh", "state": "error", "errors": 2, "last_error": "journalctl exited"}]
        });
        let text = format_status(&s);
        assert!(text.contains("web-01 (linux, Ubuntu 24.04)"));
        assert!(text.contains("last error:  HTTP 503"));
        assert!(text.contains("journalctl exited"));
    }
}
