//! Executable-runtime tests, kept private to the binary.
//!
//! The runtime's internals are deliberately not public API, so they are
//! exercised here rather than through an integration-test crate. Every test is
//! deterministic and hermetic: loopback listeners on ephemeral ports,
//! in-process certificates, controlled Tokio time where waiting matters, and a
//! Prometheus recorder local to the test thread.

mod admission;
mod configuration;
mod http;
mod lifecycle;
mod observability;
mod readiness;
mod support;
mod trace_context;
