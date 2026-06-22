//! SecureFS WebSocket server implementation
//!
//! This crate provides the server component of SecureFS, handling
//! WebSocket connections, command processing, and file system operations.

#![forbid(unsafe_code)]

pub mod config;
pub mod dao;
pub mod health;
pub mod logging;
pub mod metrics;
pub mod rate_limiter;
pub mod session_store;
pub mod storage;
