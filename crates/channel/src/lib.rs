//! SecureFS authenticated, ordered application-layer channel over an
//! established X25519 shared secret.

#![forbid(unsafe_code)]

pub mod handshake;
pub mod secure_channel;
