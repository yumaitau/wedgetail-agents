//! Running under the Windows Service Control Manager (`wedgetail-agent run --service`).
//!
//! The service is installed by the MSI as `WedgetailAgent`, running as `NT AUTHORITY\LocalService`.
//! Stop and shutdown requests set the agent's stop flag; the agent drains and exits. The
//! `paramchange` control (`sc.exe control WedgetailAgent paramchange`) reloads the
//! configuration; an invalid one is logged and the running one kept.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::mpsc;
use std::time::Duration;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use crate::Control;

pub const SERVICE_NAME: &str = "WedgetailAgent";

static CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();

// SAFETY: the macro's only `unsafe` block converts the argc/argv the Service Control Manager
// passes to the entry point into owned strings, as documented by `windows-service`.
define_windows_service!(ffi_service_main, service_main);

/// Hand the process to the Service Control Manager. Blocks until the service stops.
pub fn run(config_path: PathBuf) -> Result<(), String> {
    let _ = CONFIG_PATH.set(config_path);
    let log_dir = agent_config::paths::default_state_dir();
    let _ = std::fs::create_dir_all(&log_dir);
    crate::logger::init_file(log_dir.join("agent.log"));
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|e| format!("cannot start as a service: {e}"))
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        log::error!("service failed: {e}");
    }
}

fn status(state: ServiceState, exit: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP
                | ServiceControlAccept::SHUTDOWN
                | ServiceControlAccept::PARAM_CHANGE
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(exit),
        checkpoint: 0,
        wait_hint: Duration::from_secs(30),
        process_id: None,
    }
}

fn run_service() -> Result<(), String> {
    let (tx, rx) = mpsc::channel();
    let handle = service_control_handler::register(SERVICE_NAME, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = tx.send(Control::Stop);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::ParamChange => {
            log::info!("reload requested");
            let _ = tx.send(Control::Reload);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })
    .map_err(|e| e.to_string())?;
    handle
        .set_service_status(status(ServiceState::Running, 0))
        .map_err(|e| e.to_string())?;

    let config_path = CONFIG_PATH
        .get()
        .cloned()
        .unwrap_or_else(agent_config::paths::default_config_path);
    let result = crate::supervise(&config_path, &rx);
    // ERROR_SERVICE_SPECIFIC_ERROR-style failure code so the SCM recovery actions restart us.
    let exit = if result.is_ok() { 0 } else { 1 };
    let _ = handle.set_service_status(status(ServiceState::Stopped, exit));
    result
}
