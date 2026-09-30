//! AST for the `when` DSL (spec §7).
//!
//! Two layers: the parser produces a *raw* AST (regex patterns as strings,
//! `in` list references unresolved); `policy_file` compiles it into the
//! evaluation AST (compiled `regex::Regex`, lists resolved against the
//! policy's named lists). Compilation failures are load-time errors, which
//! keeps `reload` atomic.

use regex::Regex;

/// A field of `provio_core::ToolCallContext` addressable from the DSL.
///
/// Unknown field names are NOT a parse error: they evaluate as
/// non-matching predicates (fail-closed, never panic).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Tool,
    Command,
    Path,
    UrlHost,
    Query,
    Agent,
    Mode,
    Server,
    Trust,
    /// Any identifier not in the DSL vocabulary.
    Unknown,
}

impl Field {
    pub fn from_name(name: &str) -> Field {
        match name {
            "tool" => Field::Tool,
            "command" => Field::Command,
            "path" => Field::Path,
            // Dotted alias per INTERFACES.md Contract 1: url.host -> url_host.
            "url_host" | "url.host" => Field::UrlHost,
            "query" => Field::Query,
            "agent" => Field::Agent,
            "mode" => Field::Mode,
            "server" => Field::Server,
            // Dotted alias: server.trust -> trust.
            "trust" | "server.trust" => Field::Trust,
            _ => Field::Unknown,
        }
    }
}

/// Raw comparison operator as parsed (regex not yet compiled).
#[derive(Debug, Clone, PartialEq)]
pub enum RawOp {
    Eq(String),
    Ne(String),
    StartsWith(String),
    EndsWith(String),
    Contains(String),
    Matches(String),
}

/// Raw predicate: comparison, or membership in a named list reference
/// (e.g. `hosts.allowed`), resolved at compile time.
#[derive(Debug, Clone, PartialEq)]
pub enum RawPredicate {
    Compare { field: Field, op: RawOp },
    In { field: Field, list_ref: String },
}

/// Raw expression tree.
#[derive(Debug, Clone, PartialEq)]
pub enum RawExpr {
    Or(Box<RawExpr>, Box<RawExpr>),
    And(Box<RawExpr>, Box<RawExpr>),
    Not(Box<RawExpr>),
    Pred(RawPredicate),
}

/// Compiled comparison operator.
#[derive(Debug, Clone)]
pub enum Op {
    Eq(String),
    Ne(String),
    StartsWith(String),
    EndsWith(String),
    Contains(String),
    Matches(Regex),
}

/// Compiled predicate: `in` lists are fully resolved string sets.
#[derive(Debug, Clone)]
pub enum Predicate {
    Compare { field: Field, op: Op },
    In { field: Field, list: Vec<String> },
}

/// Compiled expression tree, evaluated against a `ToolCallContext`.
#[derive(Debug, Clone)]
pub enum Expr {
    Or(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Pred(Predicate),
}
