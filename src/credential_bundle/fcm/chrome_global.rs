use anyhow::{bail, Result};

use crate::credential_bundle::{
    base64url_decode, base64url_encode, クレデンシャル, 共通部をエンコード, 共通部をデコード,
};

const FCM_PREFIX_GLOBAL: &str = "https://fcm.googleapis.com/fcm/send/";

/// 0x11 / 0x01: Chrome グローバル FCM
pub fn エンコード_chrome_global(cred: &クレデンシャル) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    共通部をエンコード(0x11, 0x01, cred, &mut buf);

    buf.extend_from_slice(&cred.p256dh);
    buf.extend_from_slice(&[cred.auth.len() as u8]);
    buf.extend_from_slice(&cred.auth);

    let (before, after) = chrome_endpoint_parts(&cred.endpoint)?;
    buf.push(before.len() as u8);
    buf.extend_from_slice(&before);
    buf.extend_from_slice(&(after.len() as u16).to_be_bytes());
    buf.extend_from_slice(&after);
    Ok(buf)
}

pub fn デコード_chrome_global(data: &[u8]) -> Result<クレデンシャル> {
    let (exp, nonce, mut offset) = 共通部をデコード(data)?;
    if data.len() < offset + 33 + 1 {
        bail!("p256dh/auth を読み取る長さが足りません");
    }
    let p256dh = data[offset..offset + 33].to_vec();
    offset += 33;
    let auth_len = data[offset] as usize;
    offset += 1;
    if data.len() < offset + auth_len {
        bail!("auth 長さが不正");
    }
    let auth = data[offset..offset + auth_len].to_vec();
    offset += auth_len;

    if data.len() < offset + 1 {
        bail!("endpoint 前半長が不足");
    }
    let before_len = data[offset] as usize;
    offset += 1;
    if data.len() < offset + before_len + 2 {
        bail!("endpoint データが不足");
    }
    let before = &data[offset..offset + before_len];
    offset += before_len;
    let after_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;
    if data.len() < offset + after_len {
        bail!("endpoint 後半データが不足");
    }
    let after = &data[offset..offset + after_len];

    let endpoint = format!(
        "{}{}:{}",
        FCM_PREFIX_GLOBAL,
        base64url_encode(before),
        base64url_encode(after)
    );

    Ok(クレデンシャル {
        expiration_time_48: exp,
        nonce,
        p256dh,
        auth,
        endpoint,
    })
}

fn chrome_endpoint_parts(endpoint: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    if !endpoint.starts_with(FCM_PREFIX_GLOBAL) {
        bail!("想定外の endpoint プレフィックス (Chrome)");
    }
    let tail = &endpoint[FCM_PREFIX_GLOBAL.len()..];
    let parts: Vec<&str> = tail.split(':').collect();
    if parts.len() != 2 {
        bail!("endpoint に ':' 区切りがありません (Chrome)");
    }
    let before = base64url_decode(parts[0])?;
    let after = base64url_decode(parts[1])?;
    Ok((before, after))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_global_roundtrip() {
        let cred = クレデンシャル {
            expiration_time_48: 0xAABBCCDDEE,
            nonce: 0x1234,
            p256dh: vec![1; 33],
            auth: vec![2, 3, 4],
            endpoint: "https://fcm.googleapis.com/fcm/send/cxLnemDOdjY:APA91bHN6Nu3j_8Kp5VDQK_n8P3aL6Lfk908XzxiBGCMG41XwNeSSLjxLLIh_iCdbsoMo4dlMKTX8hHoDoDID0cHlZ2HR02nvQdWXwygd_oT0b-Mi0Z46fGvWn9vJUwtyKixGJoKwBZW".to_string(),
        };
        let enc = エンコード_chrome_global(&cred).unwrap();
        let dec = デコード_chrome_global(&enc).unwrap();
        assert_eq!(cred, dec);
    }
}
