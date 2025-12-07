use anyhow::{bail, Result};
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use hkdf::Hkdf;
use p256::{
    ecdh::EphemeralSecret,
    elliptic_curve::{
        sec1::{FromEncodedPoint, ToEncodedPoint},
        FieldBytes,
    },
    EncodedPoint, PublicKey, SecretKey, NistP256,
};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;

pub(crate) fn p256dhで暗号化(recipient_public_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let recipient_point = EncodedPoint::from_bytes(recipient_public_key)
        .map_err(|_| anyhow::anyhow!("受信者公開鍵の形式が不正です"))?;
    let recipient_public =
        PublicKey::from_encoded_point(&recipient_point)
            .into_option()
            .ok_or_else(|| anyhow::anyhow!("受信者公開鍵のパースに失敗しました"))?;

    let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
    let ephemeral_public = ephemeral_secret.public_key();
    let shared = ephemeral_secret.diffie_hellman(&recipient_public);
    let shared_bytes: &FieldBytes<NistP256> = shared.raw_secret_bytes();

    let hk = Hkdf::<Sha256>::new(None, shared_bytes);
    let mut key = [0u8; 32];
    hk.expand(b"credential-bundle", &mut key)
        .map_err(|_| anyhow::anyhow!("鍵導出に失敗しました"))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| anyhow::anyhow!("暗号器の初期化に失敗しました"))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|_| anyhow::anyhow!("暗号化に失敗しました"))?;

    let eph_bytes = ephemeral_public.to_encoded_point(true);
    let eph_bytes = eph_bytes.as_bytes();
    if eph_bytes.len() > u8::MAX as usize {
        bail!("公開鍵長がサポート範囲外です");
    }

    let mut out = Vec::with_capacity(1 + eph_bytes.len() + nonce_bytes.len() + ciphertext.len());
    out.push(eph_bytes.len() as u8);
    out.extend_from_slice(eph_bytes);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn p256dhで復号(ciphertext: &[u8], recipient_sk: &SecretKey) -> Result<Vec<u8>> {
    if ciphertext.len() < 1 {
        bail!("暗号文が短すぎます");
    }
    let eph_len = ciphertext[0] as usize;
    let header_len = 1 + eph_len + 12;
    if ciphertext.len() < header_len {
        bail!("暗号文ヘッダが不足しています");
    }
    let eph_bytes = &ciphertext[1..1 + eph_len];
    let nonce_bytes = &ciphertext[1 + eph_len..1 + eph_len + 12];
    let body = &ciphertext[header_len..];

    let eph_point = EncodedPoint::from_bytes(eph_bytes)
        .map_err(|_| anyhow::anyhow!("エフェメラル公開鍵の形式が不正です"))?;
    let eph_public = PublicKey::from_encoded_point(&eph_point)
        .into_option()
        .ok_or_else(|| anyhow::anyhow!("エフェメラル公開鍵のパースに失敗しました"))?;

    let shared = p256::elliptic_curve::ecdh::diffie_hellman(
        recipient_sk.to_nonzero_scalar(),
        eph_public.as_affine(),
    );
    let shared_bytes: &FieldBytes<NistP256> = shared.raw_secret_bytes();

    let hk = Hkdf::<Sha256>::new(None, shared_bytes);
    let mut key = [0u8; 32];
    hk.expand(b"credential-bundle", &mut key)
        .map_err(|_| anyhow::anyhow!("鍵導出に失敗しました"))?;

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| anyhow::anyhow!("復号器の初期化に失敗しました"))?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), body)
        .map_err(|_| anyhow::anyhow!("復号に失敗しました"))?;
    Ok(plaintext)
}
