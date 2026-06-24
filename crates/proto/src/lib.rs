//! SecureFS wire protocol vocabulary: the command set and message envelopes
//! exchanged between client and server, plus string -> command parsing.

#![forbid(unsafe_code)]

pub mod cmd;
pub mod protocol;
