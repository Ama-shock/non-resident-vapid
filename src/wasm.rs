use wasm_bindgen::prelude::*;

use crate::credential_bundle::{decode_credential_bundle, encode_credential_bundle};
use crate::subscription::購読データ;
use crate::key_store::{KeyHandle, KeyStore};

fn err(msg: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&msg.to_string())
}

#[wasm_bindgen]
pub fn encode_credential_bundle_wasm(
    subscription_json: &str,
    key_id_base64url: &str,
    public_key_base64url: &str,
    expiration_sec: u64,
) -> Result<String, JsValue> {
    let subscription: 購読データ =
        serde_json::from_str(subscription_json).map_err(|e| err(format!("購読JSONの解析に失敗: {e}")))?;

    let key_id = base64::decode_config(key_id_base64url, base64::URL_SAFE_NO_PAD)
        .map_err(|e| err(format!("鍵IDのBase64URLデコードに失敗: {e}")))?;
    let public_key = base64::decode_config(public_key_base64url, base64::URL_SAFE_NO_PAD)
        .map_err(|e| err(format!("公開鍵のBase64URLデコードに失敗: {e}")))?;

    let handle = EncodeOnlyHandle { key_id, public_key };
    let bundle = encode_credential_bundle(&subscription, &handle, expiration_sec, None)
        .map_err(err)?;
    Ok(base64::encode_config(bundle, base64::URL_SAFE_NO_PAD))
}

#[wasm_bindgen]
pub fn decode_credential_bundle_wasm(
    bundle_base64url: &str,
    key_id_base64url: &str,
    private_key_base64url: &str,
) -> Result<JsValue, JsValue> {
    let bundle = base64::decode_config(bundle_base64url, base64::URL_SAFE_NO_PAD)
        .map_err(|e| err(format!("バンドルのBase64URLデコードに失敗: {e}")))?;
    let key_id = base64::decode_config(key_id_base64url, base64::URL_SAFE_NO_PAD)
        .map_err(|e| err(format!("鍵IDのBase64URLデコードに失敗: {e}")))?;
    let private_key_bytes = base64::decode_config(private_key_base64url, base64::URL_SAFE_NO_PAD)
        .map_err(|e| err(format!("秘密鍵のBase64URLデコードに失敗: {e}")))?;

    let secret = p256::SecretKey::from_sec1_der(&private_key_bytes)
        .or_else(|_| p256::SecretKey::from_sec1_pem(std::str::from_utf8(&private_key_bytes).unwrap_or("")))
        .or_else(|_| {
            if private_key_bytes.len() == 32 {
                let fb: &p256::elliptic_curve::FieldBytes<p256::NistP256> =
                    p256::elliptic_curve::FieldBytes::<p256::NistP256>::from_slice(&private_key_bytes);
                p256::SecretKey::from_bytes(fb)
            } else {
                Err(p256::elliptic_curve::Error)
            }
        })
        .map_err(|_| err("秘密鍵の読み込みに失敗しました"))?;

    let store = WasmSingleKeyStore {
        handle: WasmHandle { key_id, secret, public: vec![] },
    };
    let subscription = decode_credential_bundle(&bundle, &store).map_err(err)?;

    let json = serde_json::to_string(&subscription).map_err(err)?;
    Ok(JsValue::from_str(&json))
}

struct EncodeOnlyHandle {
    key_id: Vec<u8>,
    public_key: Vec<u8>,
}

impl KeyHandle for EncodeOnlyHandle {
    fn key_identifier(&self) -> &[u8] {
        &self.key_id
    }
    fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }
    fn decrypt(&self, _ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        Err(anyhow::anyhow!("復号はサポートしていません"))
    }
    fn sign(&self, _message: &[u8]) -> anyhow::Result<Vec<u8>> {
        Err(anyhow::anyhow!("署名はブラウザ内では行いません"))
    }
}

struct WasmHandle {
    key_id: Vec<u8>,
    secret: p256::SecretKey,
    public: Vec<u8>,
}

impl KeyHandle for WasmHandle {
    fn key_identifier(&self) -> &[u8] {
        &self.key_id
    }
    fn public_key_bytes(&self) -> &[u8] {
        &self.public
    }
    fn decrypt(&self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        crate::credential_bundle::crypto::p256dhで復号(ciphertext, &self.secret)
    }
    fn sign(&self, _message: &[u8]) -> anyhow::Result<Vec<u8>> {
        Err(anyhow::anyhow!("WASM decode では署名は行いません"))
    }
}

struct WasmSingleKeyStore {
    handle: WasmHandle,
}

impl KeyStore for WasmSingleKeyStore {
    fn lookup(&self, key_id: &[u8; 8]) -> anyhow::Result<Box<dyn KeyHandle>> {
        if self.handle.key_id.as_slice() != key_id {
            return Err(anyhow::anyhow!("鍵IDが一致しません"));
        }
        Ok(Box::new(WasmHandle {
            key_id: self.handle.key_id.clone(),
            secret: self.handle.secret.clone(),
            public: self.handle.public.clone(),
        }))
    }
}
