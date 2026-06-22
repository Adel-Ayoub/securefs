//! SecureFS shared data models and types.
//!
//! This crate contains all the core data structures used throughout
//! the SecureFS system for representing users, files, groups, and commands.

#![forbid(unsafe_code)]

pub mod cmd;
pub mod protocol;
pub mod secure_channel;
