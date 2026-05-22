//! `haltchain-rules` — advanced policy engine for Week 3.
//!
//! Modules:
//!   * [`schema`]    — YAML DSL types (Monday)
//!   * [`evaluator`] — DAG-based rule evaluator (Tuesday)
//!   * [`conflict`]  — conflict detection graph (Wednesday)
//!   * [`watcher`]   — hot-reload file watcher (Thursday)

pub mod conflict;
pub mod evaluator;
pub mod schema;
pub mod watcher;

pub use conflict::{ConflictGraph, ConflictKind};
pub use evaluator::{EvalDecision, EvalError, RuleEvaluator, RuleOutput};
pub use schema::{
    EnforcementMode, EvalContext, FieldValue, Op, PolicyFile, Priority, Rule, RuleAction,
};
pub use watcher::{PolicyHandle, PolicyStore, watch_policy};
