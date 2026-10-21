//! `wedgetail-agent enrol`: swap a one-off enrolment token for this host's credential.
//!
//! The token is read from standard input, `WEDGETAIL_ENROL_TOKEN` or a prompt that does not
//! echo, never from the command line (other users can see arguments in the process list, and
//! they end up in shell history).

use std::fs;
use std::io::{self, Read};
use std::path::Path;

use agent_core::credential::{CredentialStore, Secret, is_enrolment_token};
use agent_core::enrolment::{ApiError, Client, EnrolRequest, EnrolmentInfo, now_s, rfc3339};
use serde_json::{Value, json};

pub const TOKEN_ENV: &str = "WEDGETAIL_ENROL_TOKEN";
/// Most bytes read from standard input when looking for the token.
const MAX_TOKEN_INPUT: u64 = 4096;

/// Shown when something that looks like a secret, or a token option, is on the command line.
pub const TOKEN_IN_ARGV: &str = "the enrolment token is never accepted on the command line, \
    where other users can see it in the process list and it is kept in shell history. Pipe it \
    on standard input or set WEDGETAIL_ENROL_TOKEN, for example:\n  \
    wedgetail-agent enrol < token.txt";

/// Arguments that must never carry a secret: token options and anything shaped like one.
pub fn is_secret_arg(arg: &str) -> bool {
    let flag = arg.split('=').next().unwrap_or(arg);
    matches!(
        flag,
        "--token" | "--enrol-token" | "--enroll-token" | "--enrolment-token" | "--credential"
    ) || arg.contains("wge_")
        || arg.contains("wgh_")
}

/// Read and check the token. In order: standard input if `force_stdin`; the environment
/// variable if set; standard input if it is not a terminal; otherwise a prompt without echo.
pub fn read_token(
    force_stdin: bool,
    env: Option<String>,
    stdin: &mut dyn Read,
    stdin_is_terminal: bool,
    prompt: &mut dyn FnMut() -> io::Result<String>,
) -> Result<Secret, String> {
    let env = env.filter(|v| !v.trim().is_empty());
    let raw = if force_stdin || (env.is_none() && !stdin_is_terminal) {
        let mut text = String::new();
        stdin
            .take(MAX_TOKEN_INPUT)
            .read_to_string(&mut text)
            .map_err(|e| format!("cannot read the enrolment token from standard input: {e}"))?;
        text
    } else if let Some(value) = env {
        value
    } else {
        prompt().map_err(|e| format!("cannot read the enrolment token: {e}"))?
    };
    let token = raw.trim();
    if token.is_empty() {
        return Err(format!(
            "no enrolment token: pipe it on standard input or set {TOKEN_ENV}"
        ));
    }
    if !is_enrolment_token(token) {
        return Err(
            "that is not an enrolment token: expected wge_ followed by 12 lower-case \
             letters or digits, _ and 43 more characters, as shown once in the Wedgetail \
             console"
                .into(),
        );
    }
    Ok(Secret::new(token.to_owned()))
}

/// Enrol and store the credential. `token` is only asked for once the local checks pass.
/// Returns the message for the user.
pub fn enrol(
    store: &dyn CredentialStore,
    endpoint: &str,
    state_dir: &Path,
    force: bool,
    token: impl FnOnce() -> Result<Secret, String>,
) -> Result<String, String> {
    let existing = EnrolmentInfo::load(state_dir).ok().flatten();
    match store.credential() {
        Ok(Some(_)) if !force => {
            let host = existing.map_or_else(String::new, |i| format!(" as host {}", i.host_id));
            return Err(format!(
                "this host is already enrolled{host} (credential in {}). To enrol it again, \
                 for example after it was revoked, run enrol with --force; revoke the old host \
                 in the console if it is still active.",
                store.location()
            ));
        }
        Err(e) if !force => {
            return Err(format!(
                "cannot read the current credential ({e}). Run as root or an administrator, \
                 or use --force to replace it."
            ));
        }
        _ => {}
    }
    check_writable(state_dir)?;
    let request = EnrolRequest::detect()?;
    let client = Client::new(endpoint)?;
    let token = token()?;
    let enrolled = client
        .enrol(&token, &request)
        .map_err(|e| enrol_error(&e, endpoint))?;
    store.store(&enrolled.credential).map_err(|e| {
        format!(
            "enrolled as host {} but cannot store the credential: {e}. Revoke that host in the \
             console and enrol again with a new token.",
            enrolled.host_id
        )
    })?;
    EnrolmentInfo::new(
        &enrolled.host_id,
        endpoint,
        enrolled.rotate_after_days,
        now_s(),
    )
    .save(state_dir)?;
    Ok(format!(
        "Enrolled this host ({}) as {} with {endpoint}.\n\
         The credential is stored in {} and rotates every {} days.\n\
         A running agent starts sending within a minute; otherwise start it:\n  {}",
        request.hostname,
        enrolled.host_id,
        store.location(),
        enrolled.rotate_after_days,
        start_hint()
    ))
}

/// Fail before using the token if the state directory cannot be written (not root, or the
/// agent is not installed).
fn check_writable(state_dir: &Path) -> Result<(), String> {
    let probe = state_dir.join(".enrol-check");
    fs::write(&probe, b"")
        .and_then(|()| fs::remove_file(&probe))
        .map_err(|e| {
            format!(
                "cannot write to {} ({e}). Run enrol as root (sudo) or an elevated \
                 administrator, after installing the agent.",
                state_dir.display()
            )
        })
}

/// The message for a failed enrolment.
pub fn enrol_error(error: &ApiError, endpoint: &str) -> String {
    match error {
        ApiError::Unauthorized => "the enrolment token was not accepted (HTTP 401). Tokens \
            expire, can be revoked and may have a use limit; create a new one in the Wedgetail \
            console under Sources, Host agents."
            .into(),
        ApiError::Unavailable {
            status,
            retry_after,
        } => format!(
            "the server is busy (HTTP {status}); try again{}.",
            retry_after.map_or_else(String::new, |d| format!(" in {} s", d.as_secs()))
        ),
        ApiError::Status {
            status: 404 | 405, ..
        } => format!(
            "{endpoint} does not accept agent enrolment ({error}); check the endpoint URL in \
             the console."
        ),
        ApiError::Status { status: 400, .. } => {
            format!("the server rejected the enrolment request ({error}).")
        }
        ApiError::Status { .. } => format!("enrolment failed ({error})."),
        ApiError::Tls(e) => format!(
            "TLS error talking to {endpoint}: {e}. Certificates are always verified: check the \
             endpoint name, and that this host trusts the server's certificate authority \
             (including any TLS-inspecting proxy)."
        ),
        ApiError::Network(e) => format!("cannot reach {endpoint}: {e}"),
        ApiError::BadResponse(e) => format!("unexpected reply from {endpoint}: {e}"),
    }
}

fn start_hint() -> &'static str {
    if cfg!(windows) {
        "Start-Service WedgetailAgent"
    } else if cfg!(target_os = "macos") {
        "sudo launchctl bootstrap system /Library/LaunchDaemons/au.com.yumait.wedgetail-agent.plist"
    } else {
        "sudo systemctl enable --now wedgetail-agent"
    }
}

/// Enrolment facts for `status`, without secrets.
pub fn status(state_dir: &Path, store: &dyn CredentialStore, now: u64) -> Value {
    let credential = match store.credential() {
        Ok(Some(_)) => "stored".to_owned(),
        Ok(None) => "missing".to_owned(),
        Err(e) => format!("unreadable: {e}"),
    };
    let mut value = match EnrolmentInfo::load(state_dir) {
        Ok(Some(info)) => {
            let issued = info.issued_at_s();
            json!({
                "enrolled": true,
                "host_id": info.host_id,
                "endpoint": info.endpoint,
                "enrolled_at": info.enrolled_at,
                "credential_issued_at": info.credential_issued_at,
                "credential_age_days": issued.map(|i| now.saturating_sub(i) / 86_400),
                "rotate_after_days": info.rotate_after_days,
                "next_rotation": info.rotate_due_s().map(rfc3339),
            })
        }
        Ok(None) => json!({ "enrolled": false }),
        Err(e) => json!({ "enrolled": null, "error": e }),
    };
    value["credential"] = credential.into();
    value["credential_store"] = store.location().into();
    value
}

/// The enrolment lines of `status`.
pub fn format_status(e: &Value) -> String {
    let text = |v: &Value| match v {
        Value::String(s) => s.clone(),
        Value::Null => "-".to_owned(),
        other => other.to_string(),
    };
    let first = match &e["enrolled"] {
        Value::Bool(true) => format!(
            "enrolment:   host {} with {} (since {})",
            text(&e["host_id"]),
            text(&e["endpoint"]),
            text(&e["enrolled_at"])
        ),
        Value::Bool(false) => "enrolment:   not enrolled (run: wedgetail-agent enrol)".to_owned(),
        _ => format!("enrolment:   {}", text(&e["error"])),
    };
    let mut lines = vec![
        first,
        format!(
            "credential:  {} in {}",
            text(&e["credential"]),
            text(&e["credential_store"])
        ),
    ];
    if e["enrolled"] == true {
        lines.push(format!(
            "rotation:    issued {} ({} days old), next rotation {}",
            text(&e["credential_issued_at"]),
            text(&e["credential_age_days"]),
            text(&e["next_rotation"])
        ));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use agent_core::FileCredential;

    use super::*;

    const TOKEN: &str = "wge_0123456789az_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO-_";
    const CRED: &str = "wgh_abc123def456_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn no_prompt() -> io::Result<String> {
        panic!("must not prompt")
    }

    fn read(
        force_stdin: bool,
        env: Option<&str>,
        stdin: &str,
        terminal: bool,
    ) -> Result<String, String> {
        read_token(
            force_stdin,
            env.map(str::to_owned),
            &mut stdin.as_bytes(),
            terminal,
            &mut no_prompt,
        )
        .map(|s| s.expose().to_owned())
    }

    #[test]
    fn token_from_stdin_env_or_prompt() {
        // Piped standard input (not a terminal), with surrounding whitespace.
        assert_eq!(
            read(false, None, &format!("  {TOKEN}\r\n"), false),
            Ok(TOKEN.into())
        );
        // The environment variable wins over a piped stdin, unless --token-stdin.
        assert_eq!(read(false, Some(TOKEN), "junk", false), Ok(TOKEN.into()));
        assert_eq!(read(true, Some("junk"), TOKEN, true), Ok(TOKEN.into()));
        // An empty variable counts as unset.
        assert_eq!(read(false, Some(" "), TOKEN, false), Ok(TOKEN.into()));
        // A terminal with no variable: prompt without echo.
        let mut prompted = false;
        let token = read_token(false, None, &mut io::empty(), true, &mut || {
            prompted = true;
            Ok(format!("{TOKEN}\n"))
        })
        .expect("prompt");
        assert!(prompted);
        assert_eq!(token.expose(), TOKEN);
    }

    #[test]
    fn token_shape_is_checked_before_sending() {
        let err = read(false, None, "", false).expect_err("empty");
        assert!(err.contains("no enrolment token"));
        for bad in [
            CRED,
            "wge_0123456789az_short",
            "wge_0123456789AZ_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO-_",
            "wge_0123456789az_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO-_ extra",
        ] {
            let err = read(false, None, bad, false).expect_err(bad);
            assert!(err.contains("not an enrolment token"), "{err}");
            assert!(!err.contains(bad), "the error must not echo the input");
        }
        // Over-long input is cut at 4 KiB rather than read without limit.
        let huge = "a".repeat(1 << 20);
        assert!(read(false, None, &huge, false).is_err());
    }

    #[test]
    fn secrets_are_refused_on_the_command_line() {
        for arg in [
            "--token",
            "--token=abc",
            "--enrol-token",
            "--enroll-token=x",
            TOKEN,
            &format!("--whatever={TOKEN}"),
            CRED,
        ] {
            assert!(is_secret_arg(arg), "{arg}");
        }
        for arg in [
            "--token-stdin",
            "--endpoint",
            "https://ingest.example.com",
            "--force",
        ] {
            assert!(!is_secret_arg(arg), "{arg}");
        }
        assert!(!TOKEN_IN_ARGV.contains("wge_"));
    }

    fn temp_state(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wt-enrol-{name}-{}-{}",
            std::process::id(),
            now_s()
        ));
        fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    #[test]
    fn refuses_to_enrol_over_an_existing_credential() {
        let dir = temp_state("existing");
        let store = FileCredential {
            path: dir.join("credential"),
        };
        store.store(&Secret::new(CRED.into())).expect("store");
        EnrolmentInfo::new("h0st00000001", "https://ingest.example.com", 30, now_s())
            .save(&dir)
            .expect("save");
        let err = enrol(&store, "https://ingest.example.com", &dir, false, || {
            panic!("the token must not be read")
        })
        .expect_err("already enrolled");
        assert!(
            err.contains("already enrolled as host h0st00000001"),
            "{err}"
        );
        assert!(err.contains("--force"));
        // The stored credential is untouched.
        assert_eq!(
            agent_core::CredentialProvider::credential(&store)
                .expect("read")
                .map(|s| s.expose().to_owned()),
            Some(CRED.to_owned())
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_state_dir_fails_before_the_token_is_used() {
        let dir = temp_state("missing").join("not-installed");
        let store = FileCredential {
            path: dir.join("credential"),
        };
        let err = enrol(&store, "https://ingest.example.com", &dir, false, || {
            panic!("the token must not be read")
        })
        .expect_err("not writable");
        assert!(err.contains("cannot write to"), "{err}");
    }

    #[test]
    fn error_messages() {
        let endpoint = "https://ingest.example.com";
        let msg = enrol_error(&ApiError::Unauthorized, endpoint);
        assert!(msg.contains("not accepted (HTTP 401)") && msg.contains("new one"));
        let msg = enrol_error(
            &ApiError::Unavailable {
                status: 429,
                retry_after: Some(std::time::Duration::from_secs(30)),
            },
            endpoint,
        );
        assert!(msg.contains("try again in 30 s"), "{msg}");
        let msg = enrol_error(
            &ApiError::Status {
                status: 404,
                message: String::new(),
            },
            endpoint,
        );
        assert!(msg.contains("check the endpoint"), "{msg}");
        let msg = enrol_error(&ApiError::Tls("invalid peer certificate".into()), endpoint);
        assert!(
            msg.contains("TLS error") && msg.contains("always verified"),
            "{msg}"
        );
        let msg = enrol_error(&ApiError::Network("connection refused".into()), endpoint);
        assert!(
            msg.contains("cannot reach https://ingest.example.com"),
            "{msg}"
        );
    }

    #[test]
    fn status_shows_enrolment_without_secrets() {
        let dir = temp_state("status");
        let store = FileCredential {
            path: dir.join("credential"),
        };
        let s = status(&dir, &store, now_s());
        assert_eq!(s["enrolled"], false);
        assert_eq!(s["credential"], "missing");
        assert!(format_status(&s).contains("not enrolled"));

        store.store(&Secret::new(CRED.into())).expect("store");
        let issued = 1_790_000_000;
        EnrolmentInfo::new("h0st00000001", "https://ingest.example.com", 30, issued)
            .save(&dir)
            .expect("save");
        let s = status(&dir, &store, issued + 3 * 86_400 + 5);
        assert_eq!(s["host_id"], "h0st00000001");
        assert_eq!(s["credential"], "stored");
        assert_eq!(s["credential_age_days"], 3);
        assert_eq!(s["next_rotation"], rfc3339(issued + 30 * 86_400));
        let text = format_status(&s);
        assert!(
            text.contains("host h0st00000001 with https://ingest.example.com"),
            "{text}"
        );
        assert!(text.contains("(3 days old)"), "{text}");
        assert!(!text.contains("wgh_") && !s.to_string().contains("wgh_"));
        let _ = fs::remove_dir_all(&dir);
    }
}
