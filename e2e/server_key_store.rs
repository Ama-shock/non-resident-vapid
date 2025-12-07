use anyhow::{bail, Result};
use non_resident_vapid::key_store::{KeyHandle, KeyStore};
use p256::SecretKey;

#[derive(Clone)]
pub struct ServerKeyHandle {
    pub key_id: Vec<u8>,
    pub secret: SecretKey,
    pub public: Vec<u8>,
}

impl KeyHandle for ServerKeyHandle {
    fn key_identifier(&self) -> &[u8] {
        &self.key_id
    }
    fn public_key_bytes(&self) -> &[u8] {
        &self.public
    }
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        non_resident_vapid::credential_bundle::crypto::p256dhで復号(ciphertext, &self.secret)
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        use p256::ecdsa::{signature::Signer, SigningKey};
        let signing: SigningKey = (&self.secret).into();
        let sig: p256::ecdsa::Signature = signing.sign(message);
        Ok(sig.to_bytes().to_vec())
    }
}

pub struct ServerKeyStore {
    handle: ServerKeyHandle,
}

impl ServerKeyStore {
    pub fn new(handle: ServerKeyHandle) -> Self {
        Self { handle }
    }
}

impl KeyStore for ServerKeyStore {
    fn lookup(&self, key_id: &[u8; 8]) -> Result<Box<dyn KeyHandle>> {
        if self.handle.key_id.as_slice() != key_id {
            bail!("鍵IDが一致しません");
        }
        Ok(Box::new(self.handle.clone()))
    }
}
