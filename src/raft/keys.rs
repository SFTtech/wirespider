use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use rand::RngExt;
use sha2::Sha256;
use sqlx::prelude::*;
use sqlx::query;
use sqlx::sqlite::SqlitePool;
use thiserror::Error;
const MASTER_KEY: &str = "master_secret";
pub const MASTER_SECRET_BYTES: usize = 32;

#[derive(Error, Debug)]
pub enum KeyError {
    #[error(transparent)]
    DbError(#[from] sqlx::Error),
    #[error("invalid master secret stored in database")]
    InvalidSecret,
}

/// Loads the node master secret from the database, creating it on first start.
///
/// The master secret is the root of the node key hierarchy: every purpose specific
/// key (raft signing, wireguard, ...) is derived from it with HKDF, so no purpose
/// ever reuses another's key material.
pub async fn load_or_create_master_secret(pool: &SqlitePool) -> Result<[u8; 32], KeyError> {
    let row = sqlx::query(r#"SELECT value FROM raft_meta WHERE key=?"#)
        .bind(MASTER_KEY)
        .fetch_optional(pool)
        .await?;
    if let Some(row) = row {
        let value: Vec<u8> = row.try_get("value")?;
        return value.try_into().map_err(|_| KeyError::InvalidSecret);
    }
    let mut secret = [0u8; MASTER_SECRET_BYTES];
    rand::rng().fill(&mut secret);
    query("INSERT INTO raft_meta (key, value) VALUES (?, ?)")
        .bind(MASTER_KEY)
        .bind(&secret[..])
        .execute(pool)
        .await?;
    Ok(secret)
}

/// Derive the ed25519 signing key used to sign raft RPCs.
pub fn raft_signing_key(master_secret: &[u8]) -> SigningKey {
    SigningKey::from_bytes(&derive(master_secret, "raft-signing"))
}

/// Derive a wireguard private key (X25519 seed) from the master secret.
pub fn wireguard_key(master_secret: &[u8]) -> [u8; 32] {
    derive(master_secret, "wireguard")
}

/// HKDF-derive a 32 byte key for `purpose` from the master secret.
pub fn derive(master_secret: &[u8], purpose: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, master_secret);
    let mut okm = [0u8; 32];
    hk.expand(purpose.as_bytes(), &mut okm)
        .expect("32 bytes is a valid HKDF output length");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purposes_produce_distinct_keys() {
        let master = [42u8; 32];
        let a = derive(&master, "wireguard");
        let b = derive(&master, "raft-signing");
        assert_ne!(a, b);
        // deterministic
        assert_eq!(a, derive(&master, "wireguard"));
    }
}
