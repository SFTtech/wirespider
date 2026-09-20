//! Signed envelopes for raft RPC payloads.
//!
//! Every node-to-node raft RPC carries an ed25519 signature made with the
//! sending node's raft key (derived from its master secret). The receiver
//! verifies the signature against the enrolled voter/learner public keys.
//! Replay protection is layered:
//! - raft itself rejects any RPC whose vote/term is older than the local one,
//! - `payload_type` binds a signature to one RPC kind (no cross-type replay),
//! - same-term replays are idempotent under raft log matching.

use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Verifier;
use ed25519_dalek::VerifyingKey;
use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;

use crate::protocol::SignedRaftPayload;

pub const TYPE_VOTE_REQUEST: &str = "raft/vote-request";
pub const TYPE_VOTE_RESPONSE: &str = "raft/vote-response";
pub const TYPE_APPEND_REQUEST: &str = "raft/append-request";
pub const TYPE_APPEND_RESPONSE: &str = "raft/append-response";
pub const TYPE_SNAPSHOT_RESPONSE: &str = "raft/snapshot-response";
pub const TYPE_SNAPSHOT_REQUEST: &str = "raft/snapshot-request";

/// Header of a snapshot transfer: everything of an
/// `InstallSnapshotRequest` except the raw data bytes. Signed by the sender.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotHeader {
    pub vote: openraft::Vote<crate::raft::NodeId>,
    pub meta: openraft::SnapshotMeta<crate::raft::NodeId, openraft::BasicNode>,
    pub offset: u64,
    pub done: bool,
}

#[derive(Error, Debug)]
pub enum SignatureEnvelopeError {
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Signature(#[from] ed25519_dalek::SignatureError),
    #[error("payload type mismatch: expected {expected}, got {got}")]
    WrongPayloadType { expected: String, got: String },
    #[error("missing payload")]
    MissingPayload,
}

/// Sign a payload with a node's raft key, producing the wire envelope.
pub fn sign_payload<T: Serialize>(
    payload: &T,
    payload_type: &str,
    key: &SigningKey,
) -> Result<SignedRaftPayload, SignatureEnvelopeError> {
    let data = serde_json::to_vec(payload)?;
    let mut signed_bytes = Vec::with_capacity(data.len() + payload_type.len());
    signed_bytes.extend_from_slice(payload_type.as_bytes());
    signed_bytes.extend_from_slice(&data);
    let signature = key.sign(&signed_bytes);
    Ok(SignedRaftPayload {
        payload: data,
        signature: signature.to_bytes().to_vec(),
        payload_type: payload_type.to_string(),
        signer: key.verifying_key().as_bytes().to_vec(),
    })
}

/// Verify and decode a signed envelope. `expected_type` must match the type
/// the signature was made over; the signer's key is returned so callers can
/// check it against the enrolled node set.
pub fn verify_and_decode<T: DeserializeOwned>(
    payload: Option<&SignedRaftPayload>,
    expected_type: &str,
) -> Result<(T, VerifyingKey), SignatureEnvelopeError> {
    let payload = payload.ok_or(SignatureEnvelopeError::MissingPayload)?;
    if payload.payload_type != expected_type {
        return Err(SignatureEnvelopeError::WrongPayloadType {
            expected: expected_type.to_string(),
            got: payload.payload_type.clone(),
        });
    }
    let signer_bytes: [u8; 32] = payload
        .signer
        .as_slice()
        .try_into()
        .map_err(|_| ed25519_dalek::SignatureError::new())?;
    let signer = VerifyingKey::from_bytes(&signer_bytes)?;
    let signature: [u8; 64] = payload
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| ed25519_dalek::SignatureError::new())?;
    let mut signed_bytes = Vec::with_capacity(payload.payload.len() + expected_type.len());
    signed_bytes.extend_from_slice(expected_type.as_bytes());
    signed_bytes.extend_from_slice(&payload.payload);
    signer.verify(
        &signed_bytes,
        &ed25519_dalek::Signature::from_bytes(&signature),
    )?;
    let decoded = serde_json::from_slice(&payload.payload)?;
    Ok((decoded, signer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let payload = "hello".to_string();
        let envelope = sign_payload(&payload, TYPE_VOTE_REQUEST, &key).unwrap();
        let (decoded, signer): (String, VerifyingKey) =
            verify_and_decode(Some(&envelope), TYPE_VOTE_REQUEST).unwrap();
        assert_eq!(decoded, payload);
        // the ed25519 pubkey is hash-derived from the seed, so compare against
        // the derived key, not the seed bytes.
        assert_eq!(signer, key.verifying_key());
    }

    #[test]
    fn wrong_type_is_rejected() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let envelope = sign_payload(&"x".to_string(), TYPE_VOTE_REQUEST, &key).unwrap();
        let err = verify_and_decode::<String>(Some(&envelope), TYPE_APPEND_REQUEST).unwrap_err();
        assert!(matches!(
            err,
            SignatureEnvelopeError::WrongPayloadType { .. }
        ));
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut envelope = sign_payload(&"x".to_string(), TYPE_VOTE_REQUEST, &key).unwrap();
        envelope.payload = serde_json::to_vec(&"y".to_string()).unwrap();
        let err = verify_and_decode::<String>(Some(&envelope), TYPE_VOTE_REQUEST).unwrap_err();
        assert!(matches!(err, SignatureEnvelopeError::Signature(_)));
    }
}
