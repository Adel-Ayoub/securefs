use aes_gcm::{Aes256Gcm, Key};
use deadpool_postgres::Pool;
use hkdf::Hkdf;
use log::{info, warn};
use rand_core::OsRng;
use securefs_model::protocol::{AppMessage, Cmd};
use sha2::Sha256;
use std::net::IpAddr;
use std::time::Instant;
use totp_rs::{Algorithm, Secret, TOTP};
use x25519_dalek::{EphemeralSecret, PublicKey};

use securefs_server::dao;

use crate::session::{RateLimiter, Session, RATE_LIMIT_WINDOW_SECS};

const MAX_LOGIN_ATTEMPTS: u8 = 5;

pub fn new_connection() -> AppMessage {
    AppMessage {
        cmd: Cmd::NewConnection,
        data: vec![],
    }
}

pub async fn login(
    data: Vec<String>,
    session: &mut Session,
    pool: &Pool,
    rate_limiter: &RateLimiter,
    client_ip: IpAddr,
) -> AppMessage {
    let (_attempts, blocked) = {
        let mut rl = rate_limiter.lock().await;
        if let Some((count, first_time)) = rl.get(&client_ip) {
            let elapsed = first_time.elapsed().as_secs();
            if elapsed > RATE_LIMIT_WINDOW_SECS {
                rl.remove(&client_ip);
                (0u8, false)
            } else {
                (*count, *count >= MAX_LOGIN_ATTEMPTS)
            }
        } else {
            (0u8, false)
        }
    };

    if blocked {
        warn!(
            "IP {} blocked due to too many failed login attempts",
            client_ip
        );
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["too many failed login attempts, try again later".to_string()],
        };
    }

    let user_name = data.first().cloned().unwrap_or_default();
    let pass = data.get(1).cloned().unwrap_or_default();
    let is_ok = dao::auth_user(pool, user_name.clone(), pass)
        .await
        .unwrap_or(false);

    if !is_ok {
        let new_count = {
            let mut rl = rate_limiter.lock().await;
            let entry = rl.entry(client_ip).or_insert((0, Instant::now()));
            entry.0 += 1;
            entry.0
        };
        audit!(
            pool,
            "LOGIN_FAIL",
            &user_name,
            &client_ip.to_string(),
            "invalid credentials"
        );
        let remaining = MAX_LOGIN_ATTEMPTS.saturating_sub(new_count);
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec![
                "failed to login!".to_string(),
                format!("{} attempts remaining", remaining),
            ],
        };
    }

    // Successful login — clear rate limiter and set session state
    {
        let mut rl = rate_limiter.lock().await;
        rl.remove(&client_ip);
    }
    session.authenticated = true;
    session.current_user = Some(user_name.clone());
    let user_home = format!("/home/{}", user_name);
    if dao::get_f_node(pool, user_home.clone())
        .await
        .ok()
        .flatten()
        .is_some()
    {
        session.current_path = user_home.clone();
    } else {
        session.current_path = "/home".into();
    }
    let user_opt = dao::get_user(pool, user_name.clone()).await.ok().flatten();
    let is_admin = user_opt.as_ref().map(|u| u.is_admin).unwrap_or(false);
    session.current_user_group = user_opt.and_then(|u| u.group_name);

    // Check if TOTP is enabled for this user
    let has_totp = dao::get_totp_secret(pool, &user_name)
        .await
        .ok()
        .flatten()
        .is_some();
    if has_totp {
        session.totp_required = true;
        audit!(
            pool,
            "LOGIN_OK",
            &user_name,
            &session.current_path,
            "totp pending"
        );
        return AppMessage {
            cmd: Cmd::Login,
            data: vec![user_name, is_admin.to_string(), "totp_required".into()],
        };
    }

    audit!(
        pool,
        "LOGIN_OK",
        &user_name,
        &session.current_path,
        "success"
    );
    AppMessage {
        cmd: Cmd::Login,
        data: vec![user_name, is_admin.to_string()],
    }
}

pub fn logout(session: &mut Session) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".to_string()],
        };
    }
    session.reset();
    AppMessage {
        cmd: Cmd::Logout,
        data: vec![],
    }
}

/// Generate a TOTP secret and return the provisioning URI.
/// The secret is stored but TOTP is not enforced until the user verifies a code.
pub async fn totp_setup(session: &Session, pool: &Pool) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".into()],
        };
    }
    let user = session.current_user.as_deref().unwrap_or("");
    let secret = Secret::generate_secret();
    let totp = match TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes().unwrap(),
        Some("SecureFS".into()),
        user.to_string(),
    ) {
        Ok(t) => t,
        Err(e) => {
            return AppMessage {
                cmd: Cmd::Failure,
                data: vec![format!("totp init failed: {}", e)],
            }
        }
    };
    let secret_b32 = secret.to_encoded().to_string();
    if let Err(e) = dao::set_totp_secret(pool, user, &secret_b32).await {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec![format!("failed to store secret: {}", e)],
        };
    }
    let uri = totp.get_url();
    audit!(pool, "TOTP_SETUP", user, "-", "secret generated");
    AppMessage {
        cmd: Cmd::TotpSetup,
        data: vec![secret_b32, uri],
    }
}

/// Verify a TOTP code. On success, clears the totp_required flag.
pub async fn totp_verify(data: Vec<String>, session: &mut Session, pool: &Pool) -> AppMessage {
    if !session.authenticated {
        return AppMessage {
            cmd: Cmd::Failure,
            data: vec!["not authenticated".into()],
        };
    }
    let user = session.current_user.as_deref().unwrap_or("");
    let code = data.first().cloned().unwrap_or_default();

    let secret_b32 = match dao::get_totp_secret(pool, user).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return AppMessage {
                cmd: Cmd::Failure,
                data: vec!["totp not configured".into()],
            }
        }
        Err(e) => {
            return AppMessage {
                cmd: Cmd::Failure,
                data: vec![format!("totp lookup failed: {}", e)],
            }
        }
    };

    let secret_bytes = match Secret::Encoded(secret_b32).to_bytes() {
        Ok(b) => b,
        Err(e) => {
            return AppMessage {
                cmd: Cmd::Failure,
                data: vec![format!("invalid secret: {}", e)],
            }
        }
    };
    let totp = match TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        None,
        user.to_string(),
    ) {
        Ok(t) => t,
        Err(e) => {
            return AppMessage {
                cmd: Cmd::Failure,
                data: vec![format!("totp init failed: {}", e)],
            }
        }
    };

    match totp.check_current(&code) {
        Ok(true) => {
            session.totp_required = false;
            audit!(pool, "TOTP_VERIFY", user, "-", "success");
            AppMessage {
                cmd: Cmd::TotpVerify,
                data: vec!["ok".into()],
            }
        }
        _ => {
            audit!(pool, "TOTP_VERIFY", user, "-", "invalid code");
            AppMessage {
                cmd: Cmd::Failure,
                data: vec!["invalid totp code".into()],
            }
        }
    }
}

/// Perform X25519 key exchange. Returns the reply message and an optional
/// shared secret to use for subsequent message encryption.
pub fn key_exchange(data: Vec<String>) -> (AppMessage, Option<Key<Aes256Gcm>>) {
    let client_pubkey_hex = data.first().cloned().unwrap_or_default();
    if client_pubkey_hex.is_empty() || client_pubkey_hex.len() != 64 {
        return (
            AppMessage {
                cmd: Cmd::Failure,
                data: vec!["invalid public key".to_string()],
            },
            None,
        );
    }

    match hex::decode(&client_pubkey_hex) {
        Ok(bytes) if bytes.len() == 32 => {
            let server_secret = EphemeralSecret::random_from_rng(OsRng);
            let server_public = PublicKey::from(&server_secret);

            let mut client_pubkey_bytes = [0u8; 32];
            client_pubkey_bytes.copy_from_slice(&bytes);
            let client_public = PublicKey::from(client_pubkey_bytes);
            let client_shared = server_secret.diffie_hellman(&client_public);

            // Derive session key using HKDF-SHA256
            let hkdf = Hkdf::<Sha256>::new(None, client_shared.as_bytes());
            let mut okm = [0u8; 32];
            hkdf.expand(b"securefs-session-key-v1", &mut okm)
                .expect("32 bytes is valid output length for HKDF-SHA256");
            let final_secret = *Key::<Aes256Gcm>::from_slice(&okm);

            info!("Key exchange completed with client");

            (
                AppMessage {
                    cmd: Cmd::KeyExchangeResponse,
                    data: vec![hex::encode(server_public.as_bytes())],
                },
                Some(final_secret),
            )
        }
        _ => (
            AppMessage {
                cmd: Cmd::Failure,
                data: vec!["invalid public key format".to_string()],
            },
            None,
        ),
    }
}
