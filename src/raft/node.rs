use std::fmt::Display;
use std::fmt::Formatter;

use serde::Deserialize;
use serde::Serialize;

/// Raft node id, derived from the node's ed25519 raft signing key.
///
/// A wrapper over the 32 byte public key so that node identities never collide and no
/// separate id registry is needed. Ordering is plain lexicographic byte order.
///
/// Serialized as a 64 character hex string: membership configs embed node ids
/// as JSON map keys, which must be strings.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId([u8; 32]);

impl Serialize for NodeId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let hex = self
            .0
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        serializer.serialize_str(&hex)
    }
}

impl<'de> Deserialize<'de> for NodeId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hex = String::deserialize(deserializer)?;
        let bytes = decode_hex(&hex).map_err(serde::de::Error::custom)?;
        Ok(NodeId(bytes))
    }
}

fn decode_hex(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err(format!("invalid node id length: {}", hex.len()));
    }
    let mut bytes = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        bytes[i] = u8::from_str_radix(std::str::from_utf8(chunk).map_err(|_| "invalid hex")?, 16)
            .map_err(|e| e.to_string())?;
    }
    Ok(bytes)
}

impl NodeId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Human readable short form: first 8 bytes as hex.
    pub fn short(&self) -> String {
        self.0
            .iter()
            .take(8)
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

/// Test compatibility: openrafts test suite builds node ids from integers.
/// The u64 is placed in the first 8 bytes, the rest is zero.
impl From<u64> for NodeId {
    fn from(value: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&value.to_be_bytes());
        Self(bytes)
    }
}

impl Display for NodeId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.short())
    }
}

impl std::fmt::Debug for NodeId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "NodeId({})", self.short())
    }
}

#[cfg(test)]
mod tests {
    use super::NodeId;

    #[test]
    fn node_id_from_u64_is_ordered() {
        let a = NodeId::from(1u64);
        let b = NodeId::from(2u64);
        assert!(a < b);
        assert_eq!(a.as_bytes()[0..8], 1u64.to_be_bytes());
    }

    #[test]
    fn node_id_serde_roundtrip() {
        let id = NodeId::from_bytes([0xab; 32]);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(
            json,
            "\"abababababababababababababababababababababababababababababababab\""
        );
        let back: NodeId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }
}
