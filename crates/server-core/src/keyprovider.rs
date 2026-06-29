use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("key material unavailable")]
    Unavailable,
}

// Source of the master key material from which at-rest data keys are derived
// (and, with envelope encryption, wrapped). Implementations may hold the key
// locally (env/file) or defer to an external KMS. Callers must never log the
// returned material; it is handed back zeroizing so it scrubs on drop.
pub trait KeyProvider {
    fn master_key(&self) -> Result<Zeroizing<Vec<u8>>, KeyError>;
}

// Master key held in process from a locally sourced secret (an env var or a
// mounted file, resolved by the caller). Both the stored secret and every copy
// handed out are zeroized on drop.
pub struct LocalKeyProvider {
    secret: Zeroizing<Vec<u8>>,
}

impl LocalKeyProvider {
    pub fn new(secret: impl Into<Vec<u8>>) -> Self {
        LocalKeyProvider {
            secret: Zeroizing::new(secret.into()),
        }
    }
}

impl KeyProvider for LocalKeyProvider {
    fn master_key(&self) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        if self.secret.is_empty() {
            return Err(KeyError::Unavailable);
        }
        Ok(Zeroizing::new(self.secret.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_the_configured_secret() {
        let p = LocalKeyProvider::new(b"super-secret".to_vec());
        assert_eq!(&**p.master_key().unwrap(), b"super-secret");
    }

    #[test]
    fn accepts_a_string_secret() {
        let p = LocalKeyProvider::new("data-key".to_string());
        assert_eq!(&**p.master_key().unwrap(), b"data-key");
    }

    #[test]
    fn empty_secret_is_unavailable() {
        let p = LocalKeyProvider::new(Vec::new());
        assert!(matches!(p.master_key(), Err(KeyError::Unavailable)));
    }
}
