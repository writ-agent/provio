//! provio-tui — terminal interface: approval gate, live call tree, cost meter.
//!
//! Dependency-free by decision (ADR-008): ANSI + line input, so the binary
//! stays statically linkable everywhere with zero terminal crates. A
//! ratatui-based full-screen UI can layer over these primitives in wave 2.

#![forbid(unsafe_code)]

pub mod gate;
pub mod meter;
pub mod tree;

pub use gate::TuiApprover;
pub use meter::{Pricing, TokenMeter};
pub use tree::{render_call_line, render_rule_note};
