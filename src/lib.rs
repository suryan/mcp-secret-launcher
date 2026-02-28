//! MCP Secret Launcher Library
//!
//! Provides core functionality for managing secrets and launching MCP servers.

/// Command-line interface definitions and parsers.
pub mod cli;
/// Error types and categories for the launcher.
pub mod errors;
/// Operations for reading and writing to the OS keyring.
pub mod keyring_ops;
/// Utilities for securely masking secret values in logs and output.
pub mod masking;
/// Interfaces and implementations for securely prompting the user for secrets.
pub mod prompter;
/// Process execution logic with secure environment variable injection.
pub mod runner;
