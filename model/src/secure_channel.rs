//! Authenticated, ordered application-layer channel over an established
//! X25519 shared secret.
//!
//! The shared secret is split into two independent AES-256-GCM keys, one per
//! direction, and every frame binds a monotonic per-direction sequence number
//! into both the nonce and the AAD. Consequences:
//!   - reflection: a frame is encrypted under the sender's send key, which is
//!     the peer's receive key, so it cannot be opened by the sender.
//!   - replay / reorder: the receiver only accepts the next expected sequence,
//!     and the nonce/AAD are derived from it, so a stale frame fails to verify.
//!   - tamper: standard AES-GCM authentication.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::protocol::AppMessage;

/// Framing version, sent during the handshake and bound into every frame's
/// AAD. Bump on any change to key derivation or wire format so mismatched
/// peers fail fast instead of silently mis-deriving keys.
pub const PROTOCOL_VERSION: u8 = 2;

const DIR_C2S: u8 = 1;
const DIR_S2C: u8 = 2;

const INFO_C2S: &[u8] = b"securefs-c2s-v2";
const INFO_S2C: &[u8] = b"securefs-s2c-v2";

/// Which end of the channel a peer is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Client,
    Server,
}

/// Error from sealing or opening a secure-channel frame.
#[derive(Debug, thiserror::Error)]
pub enum SecureChannelError {
    #[error("frame codec: {0}")]
    Codec(#[from] serde_json::Error),
    #[error("encryption failed")]
    Encrypt,
    #[error("authentication failed")]
    Decrypt,
    #[error("invalid ciphertext encoding")]
    InvalidHex,
    #[error("sequence mismatch (possible replay or reorder)")]
    SequenceMismatch,
    #[error("sequence overflow")]
    SequenceOverflow,
}

/// Per-connection channel state: a key and monotonic counter for each
/// direction.
pub struct SecureChannel {
    send_key: Key<Aes256Gcm>,
    recv_key: Key<Aes256Gcm>,
    send_dir: u8,
    recv_dir: u8,
    send_seq: u64,
    recv_seq: u64,
}

fn derive(secret: &[u8], info: &[u8]) -> Key<Aes256Gcm> {
    let hkdf = Hkdf::<Sha256>::new(None, secret);
    let mut okm = [0u8; 32];
    hkdf.expand(info, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    *Key::<Aes256Gcm>::from_slice(&okm)
}

fn nonce_for(seq: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&seq.to_be_bytes());
    n
}

fn aad_for(dir: u8, seq: u64) -> [u8; 10] {
    let mut a = [0u8; 10];
    a[0] = PROTOCOL_VERSION;
    a[1] = dir;
    a[2..].copy_from_slice(&seq.to_be_bytes());
    a
}

impl SecureChannel {
    /// Derive both per-direction keys from the raw X25519 shared secret.
    pub fn new(shared_secret: &[u8], role: Role) -> Self {
        let c2s = derive(shared_secret, INFO_C2S);
        let s2c = derive(shared_secret, INFO_S2C);
        match role {
            Role::Client => SecureChannel {
                send_key: c2s,
                recv_key: s2c,
                send_dir: DIR_C2S,
                recv_dir: DIR_S2C,
                send_seq: 0,
                recv_seq: 0,
            },
            Role::Server => SecureChannel {
                send_key: s2c,
                recv_key: c2s,
                send_dir: DIR_S2C,
                recv_dir: DIR_C2S,
                send_seq: 0,
                recv_seq: 0,
            },
        }
    }

    /// Encrypt a message into a wire frame, advancing the send counter.
    pub fn seal(&mut self, msg: &AppMessage) -> Result<String, SecureChannelError> {
        let plaintext = serde_json::to_vec(msg)?;
        let seq = self.send_seq;
        let nonce = nonce_for(seq);
        let aad = aad_for(self.send_dir, seq);
        let cipher = Aes256Gcm::new(&self.send_key);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| SecureChannelError::Encrypt)?;
        let wire = serde_json::to_string(&(hex::encode(ciphertext), seq))?;
        self.send_seq = seq
            .checked_add(1)
            .ok_or(SecureChannelError::SequenceOverflow)?;
        Ok(wire)
    }

    /// Decrypt a wire frame, enforcing the expected sequence and advancing the
    /// receive counter. Errors leave the channel unchanged so the caller can
    /// fail the connection closed.
    pub fn open(&mut self, wire: &str) -> Result<AppMessage, SecureChannelError> {
        let (ciphertext_hex, seq): (String, u64) = serde_json::from_str(wire)?;
        if seq != self.recv_seq {
            return Err(SecureChannelError::SequenceMismatch);
        }
        let ciphertext =
            hex::decode(&ciphertext_hex).map_err(|_| SecureChannelError::InvalidHex)?;
        let nonce = nonce_for(seq);
        let aad = aad_for(self.recv_dir, seq);
        let cipher = Aes256Gcm::new(&self.recv_key);
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| SecureChannelError::Decrypt)?;
        let msg = serde_json::from_slice(&plaintext)?;
        self.recv_seq = seq
            .checked_add(1)
            .ok_or(SecureChannelError::SequenceOverflow)?;
        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{AppMessage, Cmd};

    fn pair() -> (SecureChannel, SecureChannel) {
        let secret = [7u8; 32];
        (
            SecureChannel::new(&secret, Role::Client),
            SecureChannel::new(&secret, Role::Server),
        )
    }

    fn msg() -> AppMessage {
        AppMessage {
            cmd: Cmd::Pwd,
            data: vec!["hello".into()],
        }
    }

    #[test]
    fn roundtrip_both_directions() {
        let (mut client, mut server) = pair();
        let frame = client.seal(&msg()).unwrap();
        let got = server.open(&frame).unwrap();
        assert_eq!(got.cmd, Cmd::Pwd);
        assert_eq!(got.data, vec!["hello".to_string()]);

        let reply = server.seal(&msg()).unwrap();
        let got = client.open(&reply).unwrap();
        assert_eq!(got.data, vec!["hello".to_string()]);
    }

    #[test]
    fn counters_advance_over_many_frames() {
        let (mut client, mut server) = pair();
        for i in 0..50 {
            let m = AppMessage {
                cmd: Cmd::Echo,
                data: vec![i.to_string()],
            };
            let frame = client.seal(&m).unwrap();
            assert_eq!(server.open(&frame).unwrap().data, vec![i.to_string()]);
        }
    }

    #[test]
    fn replay_is_rejected() {
        let (mut client, mut server) = pair();
        let frame = client.seal(&msg()).unwrap();
        assert!(server.open(&frame).is_ok());
        // The sequence is already consumed; the same frame must not verify again.
        assert!(server.open(&frame).is_err());
    }

    #[test]
    fn reorder_is_rejected() {
        let (mut client, mut server) = pair();
        let _frame0 = client.seal(&msg()).unwrap();
        let frame1 = client.seal(&msg()).unwrap();
        // Delivering frame 1 while the receiver still expects frame 0 fails.
        assert!(server.open(&frame1).is_err());
    }

    #[test]
    fn reflection_is_rejected() {
        // A peer must not accept its own frame reflected back: the frame is
        // encrypted under the send key, which is not the peer's receive key.
        let (mut client, mut _server) = pair();
        let frame = client.seal(&msg()).unwrap();
        assert!(client.open(&frame).is_err());
    }

    #[test]
    fn tamper_is_rejected() {
        let (mut client, mut server) = pair();
        let frame = client.seal(&msg()).unwrap();
        // Flip one hex digit of the ciphertext field.
        let idx = frame.find(['a', '0']).unwrap_or(2);
        let mut bytes: Vec<char> = frame.chars().collect();
        bytes[idx] = if bytes[idx] == 'a' { 'b' } else { '1' };
        let tampered: String = bytes.into_iter().collect();
        assert!(server.open(&tampered).is_err());
    }

    #[test]
    fn wrong_secret_cannot_open() {
        let mut client = SecureChannel::new(&[1u8; 32], Role::Client);
        let mut server = SecureChannel::new(&[2u8; 32], Role::Server);
        let frame = client.seal(&msg()).unwrap();
        assert!(server.open(&frame).is_err());
    }
}
