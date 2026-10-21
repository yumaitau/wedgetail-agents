//! `wedgetail-agent`: collect host logs and ship them to Wedgetail.

// Only the Windows glue under `os/` may contain `unsafe`: the service entry macro and the DPAPI
// and file ACL FFI.
#![deny(unsafe_code)]

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use agent_config::AgentConfig;
use agent_core::enrolment::RotationOptions;
use agent_core::telemetry::{AGENT_VERSION, STATUS_FILE};
use agent_core::{Agent, CredentialStore, Stop};
use serde_json::Value;

mod enrol;
#[cfg(target_os = "macos")]
mod keychain;
mod logger;
#[cfg(windows)]
#[allow(unsafe_code)]
mod os;

const USAGE: &str = "\
Usage: wedgetail-agent <command> [options]

Commands:
  run            Run the agent in the foreground (the service manager runs this)
  enrol          Enrol this host with Wedgetail (run as root or an administrator)
  check-config   Validate agent.toml, rules.d and presets, print every problem with its
                 file and line, then exit (non-zero when invalid)
  status         Show enrolment and the running agent's last status
  version        Print the version

Options:
  --config <path>    agent.toml location (default: the OS default path)
  --json             status: print the raw status JSON
  --service          run: run as a Windows service (set by the service installer)
  --endpoint <url>   enrol: ingest URL (default: endpoint in agent.toml)
  --token-stdin      enrol: read the token from standard input even if it is a terminal
  --force            enrol: replace an existing enrolment

The enrolment token is never accepted as an argument. enrol reads it from
WEDGETAIL_ENROL_TOKEN, else from standard input when that is not a terminal,
else from a prompt that does not echo:
  wedgetail-agent enrol < token.txt

Environment:
  WEDGETAIL_LOG          error, warn, info (default) or debug
  WEDGETAIL_ENROL_TOKEN  enrol: the enrolment token

Reloading the configuration (an invalid one is reported and the running one kept):
  Linux, macOS   send SIGHUP (systemctl reload wedgetail-agent)
  Windows        sc.exe control WedgetailAgent paramchange
";

#[derive(Debug, Default)]
struct Args {
    command: String,
    config: Option<PathBuf>,
    json: bool,
    service: bool,
    endpoint: Option<String>,
    token_stdin: bool,
    force: bool,
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut parsed = Args::default();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => parsed.config = Some(args.next().ok_or("--config needs a path")?.into()),
            "--json" => parsed.json = true,
            "--service" => parsed.service = true,
            "--endpoint" => {
                parsed.endpoint = Some(args.next().ok_or("--endpoint needs a URL")?);
            }
            "--token-stdin" => parsed.token_stdin = true,
            "--force" => parsed.force = true,
            "-h" | "--help" | "help" => parsed.command = "help".into(),
            "-V" | "--version" => parsed.command = "version".into(),
            // Checked before the generic arms so a secret is never echoed in an error.
            secret if enrol::is_secret_arg(secret) => return Err(enrol::TOKEN_IN_ARGV.into()),
            flag if flag.starts_with('-') => {
                let name = flag.split('=').next().unwrap_or(flag);
                return Err(format!("unknown option {name}"));
            }
            command if parsed.command.is_empty() => parsed.command = command.to_owned(),
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }
    Ok(parsed)
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(args) => args,
        // A token on the command line gets its own message, not the usage text.
        Err(e) if e == enrol::TOKEN_IN_ARGV => return fail(&e),
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
        "enrol" | "enroll" => enrol_command(&config_path, &args),
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
fn warn(message: &str) {
    eprintln!("wedgetail-agent: warning: {message}");
}

#[allow(clippy::print_stderr)]
fn fail(message: &str) -> ExitCode {
    eprintln!("wedgetail-agent: {message}");
    ExitCode::FAILURE
}

fn load(config_path: &Path) -> Result<AgentConfig, String> {
    AgentConfig::load(config_path).map_err(|e| e.to_string())
}

/// Build the agent for a loaded config. Shared by `run`, reloads and the Windows service.
fn build_agent(config: AgentConfig) -> Result<Agent, String> {
    for warning in &config.warnings {
        log::warn!("{warning}");
    }
    let store = credential_store(&config.state_dir);
    Agent::new(config, store.clone())
        .map(|agent| agent.with_rotation(store, RotationOptions::default()))
        .map_err(|e| e.to_string())
}

/// Where this OS keeps the host credential: a 0600 file in the state directory on Linux (and
/// other Unix), DPAPI on Windows, the System keychain on macOS.
#[cfg(not(any(windows, target_os = "macos")))]
fn credential_store(state_dir: &Path) -> Arc<dyn CredentialStore> {
    Arc::new(agent_core::FileCredential {
        path: state_dir.join("credential"),
    })
}

#[cfg(windows)]
fn credential_store(state_dir: &Path) -> Arc<dyn CredentialStore> {
    Arc::new(os::windows::dpapi::DpapiCredential {
        path: state_dir.join("credential.dpapi"),
    })
}

#[cfg(target_os = "macos")]
fn credential_store(_state_dir: &Path) -> Arc<dyn CredentialStore> {
    Arc::new(keychain::KeychainCredential::system())
}

fn enrol_command(config_path: &Path, args: &Args) -> Result<(), String> {
    let config = AgentConfig::load(config_path);
    let (endpoint, state_dir) = match (&args.endpoint, config) {
        (Some(endpoint), Ok(config)) => {
            let endpoint = endpoint.trim_end_matches('/').to_owned();
            agent_config::validate_endpoint(&endpoint)?;
            if config.endpoint_base() != endpoint {
                warn(&format!(
                    "{} sends to {}; set endpoint = \"{endpoint}\" there so the agent uses \
                     this enrolment",
                    config_path.display(),
                    config.endpoint_base()
                ));
            }
            (endpoint, config.state_dir)
        }
        (Some(endpoint), Err(_)) => (
            endpoint.trim_end_matches('/').to_owned(),
            agent_config::paths::default_state_dir(),
        ),
        (None, Ok(config)) => (config.endpoint_base().to_owned(), config.state_dir),
        (None, Err(e)) => {
            return Err(format!(
                "{e}\nSet endpoint in agent.toml or pass --endpoint <url>."
            ));
        }
    };
    agent_config::validate_endpoint(&endpoint)?;
    let store = credential_store(&state_dir);
    let message = enrol::enrol(store.as_ref(), &endpoint, &state_dir, args.force, || {
        let stdin = std::io::stdin();
        let is_terminal = stdin.is_terminal();
        enrol::read_token(
            args.token_stdin,
            std::env::var(enrol::TOKEN_ENV).ok(),
            &mut stdin.lock(),
            is_terminal,
            &mut || rpassword::prompt_password("Enrolment token (not shown): "),
        )
    })?;
    out(&message);
    Ok(())
}

/// A request to the running agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Control {
    Stop,
    Reload,
}

/// Run the agent until [`Control::Stop`] (or until every sender is gone). On
/// [`Control::Reload`] the configuration is loaded again; if it is valid the pipeline restarts
/// with it, otherwise the problems are logged and the running configuration is kept. The disk
/// buffer and checkpoints carry over, so a reload neither loses nor repeats events.
pub(crate) fn supervise(config_path: &Path, control: &Receiver<Control>) -> Result<(), String> {
    let mut agent = build_agent(load(config_path)?)?;
    loop {
        let stop = Stop::new();
        let handle = {
            let stop = stop.clone();
            thread::Builder::new()
                .name("agent".into())
                .spawn(move || agent.run(stop))
                .map_err(|e| format!("cannot start the agent: {e}"))?
        };
        let next = loop {
            match control.recv_timeout(Duration::from_millis(500)) {
                Ok(Control::Stop) | Err(RecvTimeoutError::Disconnected) => break None,
                Ok(Control::Reload) => match load(config_path).and_then(build_agent) {
                    Ok(next) => break Some(next),
                    Err(e) => log::error!(
                        "reload: {} is invalid; keeping the running configuration:\n{e}",
                        config_path.display()
                    ),
                },
                Err(RecvTimeoutError::Timeout) if handle.is_finished() => break None,
                Err(RecvTimeoutError::Timeout) => {}
            }
        };
        stop.stop();
        let result = handle
            .join()
            .map_err(|_| "the agent thread panicked".to_owned())?
            .map_err(|e| e.to_string());
        match next {
            None => return result,
            Some(next) => {
                result?;
                log::info!("configuration reloaded from {}", config_path.display());
                agent = next;
            }
        }
    }
}

/// Foreground run: SIGINT and SIGTERM stop, SIGHUP reloads.
#[cfg(unix)]
fn run(config_path: &Path) -> Result<(), String> {
    use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
    let (tx, rx) = mpsc::channel();
    let mut signals = signal_hook::iterator::Signals::new([SIGHUP, SIGINT, SIGTERM])
        .map_err(|e| format!("cannot install the signal handler: {e}"))?;
    thread::Builder::new()
        .name("signals".into())
        .spawn(move || {
            for signal in signals.forever() {
                let control = if signal == SIGHUP {
                    log::info!("reload requested");
                    Control::Reload
                } else {
                    log::info!("stop requested");
                    Control::Stop
                };
                if tx.send(control).is_err() {
                    break;
                }
            }
        })
        .map_err(|e| format!("cannot start the signal thread: {e}"))?;
    supervise(config_path, &rx)
}

/// Foreground run on Windows: Ctrl+C stops. The service reloads on `paramchange`.
#[cfg(windows)]
fn run(config_path: &Path) -> Result<(), String> {
    let (tx, rx) = mpsc::channel();
    ctrlc::set_handler(move || {
        log::info!("stop requested");
        let _ = tx.send(Control::Stop);
    })
    .map_err(|e| format!("cannot install the signal handler: {e}"))?;
    supervise(config_path, &rx)
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
    let config = AgentConfig::load(config_path).map_err(|e| {
        let n = e.problems.len();
        let s = if n == 1 { "" } else { "s" };
        format!("configuration is invalid ({n} problem{s}):\n{e}")
    })?;
    for warning in &config.warnings {
        out(&format!("warning: {warning}"));
    }
    // Building the agent checks every rule type is supported on this OS.
    Agent::new(config.clone(), Arc::new(agent_core::StaticCredential(None)))
        .map_err(|e| e.to_string())?;
    let enabled = config.rules.iter().filter(|r| r.enabled).count();
    let presets = if config.presets.is_empty() {
        "none".to_owned()
    } else {
        config.presets.join(", ")
    };
    out(&format!(
        "{}: OK\n  endpoint: {}\n  state_dir: {}\n  buffer: {} MiB\n  presets: {presets}\n  rules: {enabled} enabled, {} disabled",
        config_path.display(),
        config.endpoint_base(),
        config.state_dir.display(),
        config.buffer.max_mb,
        config.rules.len() - enabled,
    ));
    for rule in &config.rules {
        let disabled = if rule.enabled { "" } else { " disabled" };
        let origin = rule
            .origin
            .as_ref()
            .map(|o| format!(" from {o}"))
            .unwrap_or_default();
        out(&format!(
            "    {} ({}, {}){disabled}{origin}",
            rule.id,
            rule.kind.name(),
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
    let enrolment = enrol::status(
        &state_dir,
        credential_store(&state_dir).as_ref(),
        agent_core::enrolment::now_s(),
    );
    if !json {
        out(&enrol::format_status(&enrolment));
    }
    let path = state_dir.join(STATUS_FILE);
    let text = std::fs::read_to_string(&path).map_err(|e| {
        format!(
            "cannot read {} ({e}); is the agent running, and are you root or an administrator?",
            path.display()
        )
    })?;
    let mut s: Value =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    if json {
        s["enrolment"] = enrolment;
        out(&serde_json::to_string_pretty(&s).map_err(|e| e.to_string())?);
    } else {
        out(&format_status(&s));
    }
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
        let a = args(&[
            "enrol",
            "--endpoint",
            "https://ingest.example.com",
            "--token-stdin",
            "--force",
        ])
        .expect("ok");
        assert_eq!(a.endpoint.as_deref(), Some("https://ingest.example.com"));
        assert!(a.token_stdin && a.force);
        assert!(args(&["enrol", "--endpoint"]).is_err());
    }

    #[test]
    fn refuses_tokens_in_argv_without_echoing_them() {
        let token = "wge_0123456789az_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO-_";
        for argv in [
            vec!["enrol", "--token", token],
            vec!["enrol", &format!("--token={token}")],
            vec!["enrol", token],
            vec![&format!("--unknown={token}"), "enrol"],
        ] {
            let err = args(&argv).expect_err("refused");
            assert_eq!(err, enrol::TOKEN_IN_ARGV, "{argv:?}");
            assert!(!err.contains(token));
        }
        let err = args(&["--bogus=secret-value"]).expect_err("unknown");
        assert_eq!(err, "unknown option --bogus");
    }

    fn config_with_rules(dir: &Path, ids: &[&str]) -> String {
        let mut text = format!(
            "[agent]\nendpoint = \"https://ingest.example.invalid\"\nstate_dir = {:?}\npresets = []\n",
            dir.join("state")
        );
        for id in ids {
            text.push_str(&format!(
                "[[rule]]\nid = \"{id}\"\ntype = \"file\"\npaths = [{:?}]\n",
                dir.join("logs").join(format!("{id}.log"))
            ));
        }
        text
    }

    fn running_rules(dir: &Path) -> Vec<String> {
        let Ok(text) = std::fs::read_to_string(dir.join("state").join(STATUS_FILE)) else {
            return Vec::new();
        };
        let status: Value = serde_json::from_str(&text).unwrap_or_default();
        status["collectors"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|c| c["rule_id"].as_str().map(str::to_owned))
            .collect()
    }

    fn wait_for_rules(dir: &Path, want: &[&str]) {
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while running_rules(dir) != want {
            assert!(
                std::time::Instant::now() < deadline,
                "still running {:?}, want {want:?}",
                running_rules(dir)
            );
            thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn reload_applies_a_valid_config_and_keeps_the_last_good_one() {
        let dir = std::env::temp_dir().join(format!("wt-cli-reload-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // Not in the config directory: rules may not read the agent's own directories.
        std::fs::create_dir_all(dir.join("etc")).expect("mkdir");
        std::fs::create_dir_all(dir.join("logs")).expect("mkdir");
        let config = dir.join("etc").join("agent.toml");
        std::fs::write(&config, config_with_rules(&dir, &["a"])).expect("write");

        let (tx, rx) = mpsc::channel();
        let supervisor = {
            let config = config.clone();
            thread::spawn(move || supervise(&config, &rx))
        };
        wait_for_rules(&dir, &["a"]);

        std::fs::write(&config, config_with_rules(&dir, &["a", "b"])).expect("write");
        tx.send(Control::Reload).expect("send");
        wait_for_rules(&dir, &["a", "b"]);

        // An invalid file is refused; the agent keeps running the last good configuration.
        std::fs::remove_file(dir.join("state").join(STATUS_FILE)).expect("rm status");
        std::fs::write(&config, "[[rule]]\nid = \"Bad Id\"\n").expect("write");
        tx.send(Control::Reload).expect("send");
        thread::sleep(Duration::from_millis(1500));
        assert!(!supervisor.is_finished());
        // status.json is rewritten every few seconds by the still-running agent.
        wait_for_rules(&dir, &["a", "b"]);

        tx.send(Control::Stop).expect("send");
        supervisor.join().expect("join").expect("clean stop");
        let _ = std::fs::remove_dir_all(&dir);
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
