mod chromium_subdomain;
mod chrome_global;

pub use chrome_global::{エンコード_chrome_global, デコード_chrome_global};
pub use chromium_subdomain::{エンコード_chromium_subdomain, デコード_chromium_subdomain};

use crate::credential_bundle::{クレデンシャル, エンコード戦略};

pub fn 戦略一覧() -> Vec<エンコード戦略> {
    vec![
        エンコード戦略 {
            型カテゴリ: 0x11,
            マイナーバージョン: 0x00,
            優先度: 0x10,
            判定: |cred: &クレデンシャル| {
                cred.endpoint.starts_with("https://")
                    && cred
                        .endpoint
                        .contains(".google.com/fcm/send/")
            },
            エンコード: |cred, _cat, _minor| エンコード_chromium_subdomain(cred),
            デコード: デコード_chromium_subdomain,
        },
        エンコード戦略 {
            型カテゴリ: 0x11,
            マイナーバージョン: 0x01,
            優先度: 0x11,
            判定: |cred: &クレデンシャル| {
                cred
                    .endpoint
                    .starts_with("https://fcm.googleapis.com/fcm/send/")
            },
            エンコード: |cred, _cat, _minor| エンコード_chrome_global(cred),
            デコード: デコード_chrome_global,
        },
    ]
}
