use anyhow::{bail, Result};

use crate::credential_bundle::{
    base64url_decode, base64url_encode, クレデンシャル, 共通部をエンコード, 共通部をデコード,
};

/// FCM (Chromium サブドメイン付き) 0x11 / 0x00
pub fn エンコード_chromium_subdomain(cred: &クレデンシャル) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    共通部をエンコード(0x11, 0x00, cred, &mut buf);

    buf.extend_from_slice(&cred.p256dh);
    buf.extend_from_slice(&[cred.auth.len() as u8]);
    buf.extend_from_slice(&cred.auth);

    let (subdomain, before, after) = chromium_endpoint_parts(&cred.endpoint)?;
    buf.push(subdomain.len() as u8);
    buf.extend_from_slice(subdomain.as_bytes());
    buf.push(before.len() as u8);
    buf.extend_from_slice(&before);
    buf.extend_from_slice(&(after.len() as u16).to_be_bytes());
    buf.extend_from_slice(&after);
    Ok(buf)
}

pub fn デコード_chromium_subdomain(data: &[u8]) -> Result<クレデンシャル> {
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
        bail!("サブドメイン長が不足");
    }
    let sub_len = data[offset] as usize;
    offset += 1;
    if data.len() < offset + sub_len {
        bail!("サブドメインが不足");
    }
    let sub = String::from_utf8(data[offset..offset + sub_len].to_vec())
        .map_err(|_| anyhow::anyhow!("サブドメインは UTF-8 である必要があります"))?;
    offset += sub_len;

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
        "https://{}.google.com/fcm/send/{}:{}",
        sub,
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

fn chromium_endpoint_parts(endpoint: &str) -> Result<(String, Vec<u8>, Vec<u8>)> {
    let prefix = "https://";
    if !endpoint.starts_with(prefix) {
        bail!("endpoint は https:// で始まる必要があります");
    }
    let rest = &endpoint[prefix.len()..];
    let parts: Vec<&str> = rest.splitn(2, ".google.com/fcm/send/").collect();
    if parts.len() != 2 {
        bail!("Chromium 向け endpoint 形式が不正です");
    }
    let subdomain = parts[0].to_string();
    let tail = parts[1];
    let split: Vec<&str> = tail.split(':').collect();
    if split.len() != 2 {
        bail!("endpoint に ':' 区切りがありません (Chromium)");
    }
    let before = base64url_decode(split[0])?;
    let after = base64url_decode(split[1])?;
    Ok((subdomain, before, after))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_cred() -> クレデンシャル {
        クレデンシャル {
            expiration_time_48: 0xAABBCCDDEE,
            nonce: 0x1234,
            p256dh: vec![1; 33],
            auth: vec![2, 3, 4],
            endpoint: "https://jmt17.google.com/fcm/send/elG2ffe5zkA:APA91bHGhXqSUl1Vcki_pRzoYcj8TYEXYnyGSSB1IjUmGbOrO915xP9f0GB0MnK4epvTBcsHGJyTT4uoKBV5CFFPt8GRgTuHpxw-plzRb1Zvn2jdN1jKyIaE0-pvwsZWExx68lsteeFV".to_string(),
        }
    }

    #[test]
    fn chromium_subdomain_roundtrip() {
        let cred = base_cred();
        let enc = エンコード_chromium_subdomain(&cred).unwrap();
        let dec = デコード_chromium_subdomain(&enc).unwrap();
        assert_eq!(cred, dec);
    }
}
