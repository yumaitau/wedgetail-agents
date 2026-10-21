//! Windows glue: the service entry point, the DPAPI credential store and the read-only audit
//! checks for `status`. The only place in this crate where `unsafe` is allowed: the
//! `windows-service` entry point macro expands to an `unsafe` block, and DPAPI and ACL calls
//! are FFI. Each `unsafe` block has a `SAFETY` note.

pub mod windows;
