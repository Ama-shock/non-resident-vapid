use anyhow::{bail, Result};

use crate::credential_bundle::{
    base64url_decode, base64url_encode, クレデンシャル, 共通部をエンコード, 共通部をデコード,
    エンコード戦略,
};

const PREF_MAIN: &str = "https://push.services.mozilla.com/wpush/v2/";
const PREF_UPDATES: &str = "https://updates.push.services.mozilla.com/wpush/v2/";

/// 0x21 / 0x00: Firefox / Autopush
pub fn エンコード_autopush初版(cred: &クレデンシャル, _cat: u8, _minor: u8) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    共通部をエンコード(0x21, 0x00, cred, &mut buf);

    buf.extend_from_slice(&cred.p256dh);
    buf.extend_from_slice(&[cred.auth.len() as u8]);
    buf.extend_from_slice(&cred.auth);

    let (prefix_id, token) = endpoint_parts(&cred.endpoint)?;
    buf.push(prefix_id);
    buf.extend_from_slice(&(token.len() as u16).to_be_bytes());
    buf.extend_from_slice(&token);
    Ok(buf)
}

pub fn デコード_autopush初版(data: &[u8]) -> Result<クレデンシャル> {
    let (exp, nonce, mut offset) = 共通部をデコード(data)?;
    if data.len() < offset + 33 + 1 {
        bail!("p256dh/auth を読み取る長さが足りません");
    }
    let p256dh = data[offset..offset + 33].to_vec();
    offset += 33;
    let auth_len = data[offset] as usize;
    offset += 1;
    if data.len() < offset + auth_len + 3 {
        bail!("auth または endpoint データが不足");
    }
    let auth = data[offset..offset + auth_len].to_vec();
    offset += auth_len;

    let prefix_id = data[offset];
    offset += 1;
    let token_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;
    if data.len() < offset + token_len {
        bail!("token 長さが不足");
    }
    let token = &data[offset..offset + token_len];
    let prefix = match prefix_id {
        0x00 => PREF_MAIN,
        0x01 => PREF_UPDATES,
        _ => bail!("未知のプレフィックス ID: {}", prefix_id),
    };
    let endpoint = format!("{}{}", prefix, base64url_encode(token));

    Ok(クレデンシャル {
        expiration_time_48: exp,
        nonce,
        p256dh,
        auth,
        endpoint,
    })
}

fn endpoint_parts(endpoint: &str) -> Result<(u8, Vec<u8>)> {
    if let Some(rest) = endpoint.strip_prefix(PREF_MAIN) {
        let token = base64url_decode(rest)?;
        return Ok((0x00, token));
    }
    if let Some(rest) = endpoint.strip_prefix(PREF_UPDATES) {
        let token = base64url_decode(rest)?;
        return Ok((0x01, token));
    }
    bail!("Autopush endpoint のプレフィックスが想定外です");
}

pub fn 戦略一覧() -> Vec<エンコード戦略> {
    vec![エンコード戦略 {
        型カテゴリ: 0x21,
        マイナーバージョン: 0x00,
        優先度: 0x20,
        判定: |cred: &クレデンシャル| {
            cred
                .endpoint
                .starts_with("https://push.services.mozilla.com/wpush/v2/")
                || cred
                    .endpoint
                    .starts_with("https://updates.push.services.mozilla.com/wpush/v2/")
        },
        エンコード: |cred, _cat, _minor| エンコード_autopush初版(cred, _cat, _minor),
        デコード: デコード_autopush初版,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autopush_roundtrip() {
        let cred = クレデンシャル {
            expiration_time_48: 0x123456789ABC,
            nonce: 0xBEEF,
            p256dh: vec![7; 33],
            auth: vec![8, 9],
            endpoint: format!("{}{}", PREF_MAIN, "YWJjZA"),
        };
        let enc = エンコード_autopush初版(&cred, 0x21, 0x00).unwrap();
        let dec = デコード_autopush初版(&enc).unwrap();
        assert_eq!(cred, dec);
    }
}
