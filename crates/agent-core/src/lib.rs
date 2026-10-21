//! The Wedgetail agent runtime.
//!
//! - [`agent::Agent`] wires collectors, the [`processor::Processor`] hook, the
//!   [`buffer::DiskBuffer`], the [`shipper::Shipper`] and the heartbeat together.
//! - [`credential::CredentialProvider`] supplies the host credential before every request;
//!   [`credential::CredentialStore`] also replaces it. [`enrolment`] enrols the host and
//!   rotates the credential in the background.

#![forbid(unsafe_code)]

pub mod agent;
pub mod backoff;
pub mod batch;
pub mod buffer;
pub mod checkpoints;
pub mod credential;
pub mod enrolment;
pub mod host;
pub mod processor;
pub mod shipper;
pub mod stop;
pub mod telemetry;

pub use agent::{Agent, AgentError};
pub use credential::{
    CredentialProvider, CredentialStore, FileCredential, Secret, StaticCredential,
};
pub use processor::{PassThrough, Processor, Verdict};
pub use stop::Stop;
