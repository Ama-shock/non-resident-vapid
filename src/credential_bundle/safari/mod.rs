mod base64_token;
mod plain_token;

pub use base64_token::{エンコード_safari_base64, デコード_safari_base64};
pub use plain_token::{エンコード_safari_plain, デコード_safari_plain};

use crate::credential_bundle::{クレデンシャル, エンコード戦略};

pub fn 戦略一覧() -> Vec<エンコード戦略> {
    vec![
        エンコード戦略 {
            型カテゴリ: 0x31,
            マイナーバージョン: 0x00,
            優先度: 0x30,
            判定: |cred: &クレデンシャル| cred
                .endpoint
                .starts_with("https://webpush.apple.com/api/push/")
                && base64_token::token_from_endpoint(cred.endpoint.as_str()).map(|t| base64_token::is_base64url(&t)).unwrap_or(false),
            エンコード: |cred, _cat, _minor| エンコード_safari_base64(cred, _cat, _minor),
            デコード: デコード_safari_base64,
        },
        エンコード戦略 {
            型カテゴリ: 0x31,
            マイナーバージョン: 0x01,
            優先度: 0x31,
            判定: |cred: &クレデンシャル| cred
                .endpoint
                .starts_with("https://webpush.apple.com/api/push/"),
            エンコード: |cred, _cat, _minor| エンコード_safari_plain(cred, _cat, _minor),
            デコード: デコード_safari_plain,
        },
    ]
}
