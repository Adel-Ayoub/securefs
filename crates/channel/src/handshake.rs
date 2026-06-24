//! X25519 key-exchange handshake that establishes a [`SecureChannel`].
//!
//! The wire shape is unchanged from when this was hand-inlined at each call
//! site: an ephemeral X25519 public key hex-encoded into `data[0]` and the
//! framing version stringified into `data[1]`, carried by `KeyExchangeInit`
//! (client to server) and `KeyExchangeResponse` (server to client).

use rand_core::OsRng;
use securefs_proto::protocol::{AppMessage, Cmd};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::secure_channel::{Role, SecureChannel, PROTOCOL_VERSION};

/// Why a handshake message could not be turned into a channel. Callers map
/// these onto their own user-facing strings.
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("protocol version mismatch")]
    Version,
    #[error("malformed public key")]
    Pubkey,
    #[error("wrong public key length")]
    PubkeyLength,
}

fn decode_peer_pubkey(hex_str: &str) -> Result<PublicKey, HandshakeError> {
    let bytes = hex::decode(hex_str).map_err(|_| HandshakeError::Pubkey)?;
    if bytes.len() != 32 {
        return Err(HandshakeError::PubkeyLength);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(PublicKey::from(arr))
}

fn version_matches(data: &[String]) -> bool {
    data.get(1).and_then(|v| v.parse::<u8>().ok()) == Some(PROTOCOL_VERSION)
}

/// Client-side handshake: holds the ephemeral secret between sending the init
/// and receiving the response.
pub struct ClientHandshake {
    secret: EphemeralSecret,
}

impl ClientHandshake {
    /// Generate an ephemeral keypair and the `KeyExchangeInit` to send.
    pub fn initiate() -> (Self, AppMessage) {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let msg = AppMessage {
            cmd: Cmd::KeyExchangeInit,
            data: vec![hex::encode(public.as_bytes()), PROTOCOL_VERSION.to_string()],
        };
        (Self { secret }, msg)
    }

    /// Derive the client-side channel from the server's `KeyExchangeResponse`
    /// data (`[pubkey_hex, version]`).
    pub fn complete(self, response: &[String]) -> Result<SecureChannel, HandshakeError> {
        if !version_matches(response) {
            return Err(HandshakeError::Version);
        }
        let peer = decode_peer_pubkey(&response.first().cloned().unwrap_or_default())?;
        let shared = self.secret.diffie_hellman(&peer);
        Ok(SecureChannel::new(shared.as_bytes(), Role::Client))
    }
}

/// Server-side: derive the channel from the client's public key and return it
/// alongside the server's own public key (hex) for the `KeyExchangeResponse`.
/// The caller owns version and presence validation so it can shape its own
/// failure replies.
pub fn derive_server_channel(
    client_pubkey_hex: &str,
) -> Result<(SecureChannel, String), HandshakeError> {
    let peer = decode_peer_pubkey(client_pubkey_hex)?;
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let shared = secret.diffie_hellman(&peer);
    let channel = SecureChannel::new(shared.as_bytes(), Role::Server);
    Ok((channel, hex::encode(public.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_establishes_a_working_channel() {
        let (client_hs, init) = ClientHandshake::initiate();
        assert_eq!(init.cmd, Cmd::KeyExchangeInit);

        let (mut server_ch, server_pubkey_hex) = derive_server_channel(&init.data[0]).unwrap();
        let response = vec![server_pubkey_hex, PROTOCOL_VERSION.to_string()];
        let mut client_ch = client_hs.complete(&response).unwrap();

        // The two ends agree: a frame the client seals, the server opens.
        let msg = AppMessage {
            cmd: Cmd::Pwd,
            data: vec!["ping".into()],
        };
        let frame = client_ch.seal(&msg).unwrap();
        assert_eq!(
            server_ch.open(&frame).unwrap().data,
            vec!["ping".to_string()]
        );
    }

    #[test]
    fn complete_rejects_version_mismatch() {
        let (client_hs, _) = ClientHandshake::initiate();
        let response = vec!["00".repeat(32), (PROTOCOL_VERSION + 1).to_string()];
        assert!(matches!(
            client_hs.complete(&response),
            Err(HandshakeError::Version)
        ));
    }

    #[test]
    fn complete_rejects_short_pubkey() {
        let (client_hs, _) = ClientHandshake::initiate();
        let response = vec!["abcd".to_string(), PROTOCOL_VERSION.to_string()];
        assert!(matches!(
            client_hs.complete(&response),
            Err(HandshakeError::PubkeyLength)
        ));
    }

    #[test]
    fn server_rejects_non_hex_pubkey() {
        assert!(matches!(
            derive_server_channel(&"zz".repeat(32)),
            Err(HandshakeError::Pubkey)
        ));
    }
}
