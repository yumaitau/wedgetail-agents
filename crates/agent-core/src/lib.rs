//! The Wedgetail agent runtime.
//!
//! - [`agent::Agent`] wires collectors, the [`processor::Processor`] hook, the
//!   [`buffer::DiskBuffer`], the [`shipper::Shipper`] and the heartbeat together.
//! - [`credential::CredentialProvider`] is where enrolment plugs in the host credential.

#![forbid(unsafe_code)]

pub mod agent;
pub mod backoff;
pub mod batch;
pub mod buffer;
pub mod checkpoints;
pub mod credential;
pub mod host;
pub mod processor;
pub mod shipper;
pub mod stop;
pub mod telemetry;

pub use agent::{Agent, AgentError};
pub use credential::{CredentialProvider, FileCredential, Secret, StaticCredential};
pub use processor::{PassThrough, Processor, Verdict};
pub use stop::Stop;
