use futures_util::{SinkExt, StreamExt};
use securefs_channel::secure_channel::{decode_frame, encode_frame, SecureChannel};
use securefs_proto::protocol::AppMessage;
use tokio_tungstenite::tungstenite::Message;

pub type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Seal and send a message over the secure channel (plaintext when None).
pub async fn send(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    msg: &AppMessage,
    channel: Option<&mut SecureChannel>,
) -> Result<(), String> {
    let payload = encode_frame(channel, msg).map_err(|e| e.to_string())?;
    ws.send(Message::Text(payload.into()))
        .await
        .map_err(|e| format!("send failed: {}", e))
}

/// Receive and open a message from the secure channel (plaintext when None).
pub async fn recv(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    channel: Option<&mut SecureChannel>,
) -> Result<AppMessage, String> {
    let msg = ws
        .next()
        .await
        .ok_or("connection closed".to_string())?
        .map_err(|e| format!("recv failed: {}", e))?;
    if !msg.is_text() {
        return Err("non-text message".into());
    }
    let text = msg.to_text().unwrap();

    decode_frame(channel, text).map_err(|e| e.to_string())
}
