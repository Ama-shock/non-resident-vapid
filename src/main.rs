//! VAPID 署名付き Web Push を送信するための CLI。クレデンシャルバンドル化前の疎通確認用。

mod push_sender;

use anyhow::{Context, Result};
use clap::Parser;
use push_sender::{pushを送信, ソフトウェアキーストア, 購読データ};
use std::{fs, path::PathBuf};

#[derive(Parser, Debug)]
#[command(name = "non-resident-vapid", about = "VAPID 署名付き Web Push 送信ツール")]
struct 引数 {
    /// e2e/subscription.json などで保存した購読情報ファイル
    #[arg(long = "subscription-file")]
    購読ファイル: PathBuf,

    /// VAPID 公開鍵（base64url, padding 無し）※現状は署名検証のためにのみ使用
    #[arg(long = "vapid-public-key")]
    vapid公開鍵: Option<String>,

    /// VAPID 秘密鍵（base64url, padding 無し）※TPM/HSM 未接続環境での暫定入力
    #[arg(long = "vapid-private-key")]
    vapid秘密鍵: Option<String>,

    /// VAPID 鍵の JSON ファイル（例: e2e/output/vapid_keys.json）。指定時は公開鍵・秘密鍵引数を不要とする。
    #[arg(long = "vapid-keys-file", conflicts_with_all = ["vapid_public_key", "vapid_private_key"])]
    vapid鍵ファイル: Option<PathBuf>,

    /// サブスクライバ識別用の subject（例: mailto:example@example.com）
    #[arg(long = "subject", default_value = "mailto:example@example.com")]
    subject: String,

    /// 送信する本文
    #[arg(long = "payload", default_value = "non-resident-vapid からのテストメッセージ")]
    本文: String,

    /// TTL (秒)
    #[arg(long = "ttl", default_value_t = 60)]
    ttl: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    let 引数 = 引数::parse();

    let 購読ファイル内容 =
        fs::read_to_string(&引数.購読ファイル).with_context(|| "購読ファイルの読み込みに失敗")?;
    let 購読: 購読データ =
        serde_json::from_str(&購読ファイル内容).with_context(|| "購読 JSON の解析に失敗")?;

    let (_vapid公開鍵, vapid秘密鍵) =
        vapid鍵を読み込み(&引数.vapid公開鍵, &引数.vapid秘密鍵, &引数.vapid鍵ファイル)?;

    let 署名提供者 = ソフトウェアキーストア::new(vapid秘密鍵);
    pushを送信(
        &購読,
        &引数.本文,
        引数.ttl,
        &引数.subject,
        &署名提供者,
    )
    .await?;

    println!("送信完了: Web Push を送信しました。");
    Ok(())
}

fn vapid鍵を読み込み(
    vapid公開鍵: &Option<String>,
    vapid秘密鍵: &Option<String>,
    vapid鍵ファイル: &Option<PathBuf>,
) -> Result<(String, String)> {
    if let Some(ファイル) = vapid鍵ファイル {
        let 内容 = fs::read_to_string(ファイル)
            .with_context(|| format!("VAPID 鍵ファイルの読み込みに失敗: {}", ファイル.display()))?;
        #[derive(serde::Deserialize)]
        struct 鍵ファイル形式 {
            vapid公開鍵: String,
            vapid秘密鍵: String,
        }
        let 鍵: 鍵ファイル形式 =
            serde_json::from_str(&内容).with_context(|| "VAPID 鍵 JSON の解析に失敗")?;
        return Ok((鍵.vapid公開鍵, 鍵.vapid秘密鍵));
    }

    match (vapid公開鍵, vapid秘密鍵) {
        (Some(pk), Some(sk)) => Ok((pk.clone(), sk.clone())),
        _ => Err(anyhow::anyhow!(
            "VAPID 鍵が不足しています。--vapid-keys-file で JSON を渡すか、--vapid-public-key と --vapid-private-key を併用してください。"
        )),
    }
}
