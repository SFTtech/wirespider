use std::marker::PhantomData;

use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json;

use super::PeerId;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SignatureError {
    #[error(transparent)]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    SignatureError(#[from] ed25519_dalek::SignatureError),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Signed<T> {
    phantom_data: PhantomData<*const T>,
    serialized: String,
    key: PeerId,
    signature: Signature,
}

impl<'de, T: Serialize + Deserialize<'de>> Signed<T> {
    fn new(data: T, key: &ed25519_dalek::SigningKey) -> Result<Self, SignatureError> {
        let serialized = serde_json::to_string(&data)?;
        let signature = key.sign(serialized.as_bytes());
        let key = key.verifying_key();
        Ok(Self {
            phantom_data: PhantomData,
            serialized,
            key,
            signature,
        })
    }

    fn from_serialized(serialized: String, key: VerifyingKey, signature: Signature) -> Self {
        Self {
            phantom_data: PhantomData,
            serialized,
            key,
            signature,
        }
    }

    fn get_inner(self: &'de Self) -> Result<T, SignatureError> {
        self.key
            .verify(&self.serialized.as_bytes(), &self.signature)?;
        Ok(serde_json::from_str(&self.serialized)?)
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use crate::rpc::signed::Signed;

    #[test]
    fn test_new_signed() {
        let mut csprng = rand::rngs::OsRng {};
        let keypair = SigningKey::generate(&mut csprng);
        let test_string = "Test123123123";
        let signed = Signed::new(test_string.clone(), &keypair).unwrap();
        assert_eq!(signed.get_inner().unwrap(), test_string);
    }

    #[test]
    fn test_from_signature() {
        let mut csprng = rand::rngs::OsRng {};
        let signing_key = SigningKey::generate(&mut csprng);
        let test_string = "abcde";
        let serialized = serde_json::to_string(test_string).unwrap();
        let signature = signing_key.sign(serialized.as_bytes());
        let signed: Signed<String> = Signed::from_serialized(serialized, signing_key, signature);
        assert_eq!(signed.get_inner().unwrap(), test_string);
        assert_eq!(signed.signature(), &signature);
    }
}
