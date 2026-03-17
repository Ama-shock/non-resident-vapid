use anyhow::{bail, Result};

use crate::credential_bundle::{
    クレデンシャル, 共通部をエンコード, 共通部をデコード,
    エンコード戦略,
};

/// WNS (Windows Notification Service) — Edge ブラウザ
///
/// エンドポイント形式:
///   https://<subdomain>.notify.windows.com/w/?token=<url-encoded-token>
///
/// 短縮:
///   - プレフィックス "https://" + サフィックス ".notify.windows.com/w/?token=" を省略
///   - サブドメイン文字列を 1 バイト長 + UTF-8 で格納
///   - トークンは URL デコードしてバイナリで格納

const SUFFIX: &str = ".notify.windows.com/w/?token=";

/// 0x41 / 0x00: WNS 初版
pub fn エンコード_wns初版(cred: &クレデンシャル, _cat: u8, _minor: u8) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    共通部をエンコード(0x41, 0x00, cred, &mut buf);

    buf.extend_from_slice(&cred.p256dh);
    buf.extend_from_slice(&[cred.auth.len() as u8]);
    buf.extend_from_slice(&cred.auth);

    let (subdomain, token_bytes) = endpoint_parts(&cred.endpoint)?;
    buf.push(subdomain.len() as u8);
    buf.extend_from_slice(subdomain.as_bytes());
    buf.extend_from_slice(&(token_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(&token_bytes);
    Ok(buf)
}

pub fn デコード_wns初版(data: &[u8]) -> Result<クレデンシャル> {
    let (exp, nonce, mut offset) = 共通部をデコード(data)?;
    if data.len() < offset + 33 + 1 {
        bail!("p256dh/auth を読み取る長さが足りません");
    }
    let p256dh = data[offset..offset + 33].to_vec();
    offset += 33;
    let auth_len = data[offset] as usize;
    offset += 1;
    if data.len() < offset + auth_len + 1 {
        bail!("auth またはサブドメインデータが不足");
    }
    let auth = data[offset..offset + auth_len].to_vec();
    offset += auth_len;

    let sub_len = data[offset] as usize;
    offset += 1;
    if data.len() < offset + sub_len + 2 {
        bail!("サブドメインデータが不足");
    }
    let subdomain = String::from_utf8(data[offset..offset + sub_len].to_vec())
        .map_err(|_| anyhow::anyhow!("サブドメインは UTF-8 である必要があります"))?;
    offset += sub_len;

    let token_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;
    if data.len() < offset + token_len {
        bail!("トークン長さが不足");
    }
    let token_bytes = &data[offset..offset + token_len];

    // URL エンコードして元のエンドポイントを復元
    let token_encoded = url_encode(token_bytes);
    let endpoint = format!("https://{}{}{}", subdomain, SUFFIX, token_encoded);

    Ok(クレデンシャル {
        expiration_time_48: exp,
        nonce,
        p256dh,
        auth,
        endpoint,
    })
}

fn endpoint_parts(endpoint: &str) -> Result<(String, Vec<u8>)> {
    let rest = endpoint
        .strip_prefix("https://")
        .ok_or_else(|| anyhow::anyhow!("WNS endpoint は https:// で始まる必要があります"))?;
    let idx = rest
        .find(SUFFIX)
        .ok_or_else(|| anyhow::anyhow!("WNS endpoint のサフィックスが見つかりません"))?;
    let subdomain = rest[..idx].to_string();
    let token_str = &rest[idx + SUFFIX.len()..];
    let token_bytes = url_decode(token_str)?;
    Ok((subdomain, token_bytes))
}

/// パーセントエンコードされた文字列をバイト列にデコード
fn url_decode(input: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chars = input.as_bytes().iter();
    while let Some(&c) = chars.next() {
        if c == b'%' {
            let hi = chars.next().ok_or_else(|| anyhow::anyhow!("不正な % エンコード"))?;
            let lo = chars.next().ok_or_else(|| anyhow::anyhow!("不正な % エンコード"))?;
            let hex = [*hi, *lo];
            let s = std::str::from_utf8(&hex)
                .map_err(|_| anyhow::anyhow!("不正な hex 文字"))?;
            let byte = u8::from_str_radix(s, 16)
                .map_err(|_| anyhow::anyhow!("不正な hex 値"))?;
            bytes.push(byte);
        } else {
            bytes.push(c);
        }
    }
    Ok(bytes)
}

/// バイト列をパーセントエンコード (RFC 3986 unreserved 以外をエンコード)
fn url_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &b in bytes {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

pub fn 戦略一覧() -> Vec<エンコード戦略> {
    vec![エンコード戦略 {
        型カテゴリ: 0x41,
        マイナーバージョン: 0x00,
        優先度: 0x40,
        判定: |cred: &クレデンシャル| {
            cred.endpoint.starts_with("https://")
                && cred.endpoint.contains(".notify.windows.com/w/?token=")
        },
        エンコード: エンコード_wns初版,
        デコード: デコード_wns初版,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wns_roundtrip() {
        let cred = クレデンシャル {
            expiration_time_48: 0x123456789ABC,
            nonce: 0xBEEF,
            p256dh: vec![7; 33],
            auth: vec![8, 9],
            endpoint: "https://wns2-pn1p.notify.windows.com/w/?token=BQYAAABGKuKev6Zs69hr41ITOM1NZ3j%2Ftest%3D%3D".to_string(),
        };
        let enc = エンコード_wns初版(&cred, 0x41, 0x00).unwrap();
        let dec = デコード_wns初版(&enc).unwrap();
        assert_eq!(cred.endpoint, dec.endpoint);
        assert_eq!(cred.p256dh, dec.p256dh);
        assert_eq!(cred.auth, dec.auth);
        assert_eq!(cred.expiration_time_48, dec.expiration_time_48);
        assert_eq!(cred.nonce, dec.nonce);
    }

    #[test]
    fn wns_full_token_roundtrip() {
        // 実際の Edge エンドポイントに近い形式
        // URL エンコードの大文字/小文字の差異は意味的に同一なので、
        // バイト列レベルで比較する
        let cred = クレデンシャル {
            expiration_time_48: 1700000000,
            nonce: 0x0001,
            p256dh: vec![3; 33],
            auth: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            endpoint: "https://wns2-pn1p.notify.windows.com/w/?token=BQYAAABGKuKev6Zs69hr41ITOM1NZ3jtosVbhun0Er2MlD8TZ%2fTFvbDv%2bzDvu613ta2yAvGR8u21DATeQ1txj2ceEMNnkvt0aO16lKzL8ryJtu%2blN9A6Ri7gnbm8ZuOv5e1kDxM540d6prpYkh11zvvn0tfLdj6cn1MW1BI0YP3lcITTihwIR8eq%2fumpuE0VxkTwN7ogRe8Lxnu83LAhZENoe5U%2bAVlJvmi%2bOO6HO%2fznGmhgoPmfz4%2ft5RSgbLqTYpgEbEhko7F5Aty4FudksY8dIixZOX0YVK%2bAxw84F3Qidmo8f52AQ2R0%2b6bBNGOlTq%2flAXVmbI5AiSskzqnnSFjS4R2dT7w229%2fAafbzb0SlA7eNQw%3d%3d".to_string(),
        };
        let enc = エンコード_wns初版(&cred, 0x41, 0x00).unwrap();
        let dec = デコード_wns初版(&enc).unwrap();
        // URL デコードしたバイト列が一致すれば OK
        let (_, orig_token) = endpoint_parts(&cred.endpoint).unwrap();
        let (_, decoded_token) = endpoint_parts(&dec.endpoint).unwrap();
        assert_eq!(orig_token, decoded_token);
        assert_eq!(cred.p256dh, dec.p256dh);
        assert_eq!(cred.auth, dec.auth);
    }

    #[test]
    fn url_encode_decode_roundtrip() {
        let original = "BQYAAABGKuKev6Zs69hr41ITOM1NZ3j/test==";
        let bytes = url_decode(
            &original.replace('/', "%2f").replace('=', "%3d").replace('+', "%2b"),
        )
        .unwrap();
        let encoded = url_encode(&bytes);
        let decoded = url_decode(&encoded).unwrap();
        assert_eq!(bytes, decoded);
    }
}
