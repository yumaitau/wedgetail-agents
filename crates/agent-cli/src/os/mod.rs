//! OS service glue. The only place in this crate where `unsafe` is allowed, and only because
//! the `windows-service` entry point macro expands to an `unsafe` block.

pub mod windows;
