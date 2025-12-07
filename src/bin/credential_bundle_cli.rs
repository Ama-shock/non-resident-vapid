//! クレデンシャルバンドルのエンコード・デコード補助 CLI。E2E テストでも利用する。

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use non_resident_vapid::credential_bundle::{decode_credential_bundle, encode_credential_bundle};
use non_resident_vapid::key_store::{KeyHandle, KeyStore};
use non_resident_vapid::credential_bundle::crypto;
use non_resident_vapid::subscription::購読データ;
use p256::{SecretKey, NistP256};
type P256FieldBytes = p256::elliptic_curve::FieldBytes<NistP256>;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "credential-bundle-cli", about = "クレデンシャルバンドルの補助ツール")]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// 購読情報からクレデンシャルバンドルを生成する
    Encode {
        /// 購読 JSON ファイル（p256dh/auth は Base64URL 文字列）
        #[arg(long)]
        subscription_file: PathBuf,
        /// 鍵識別子（Base64URL, 8バイト）
        #[arg(long)]
        key_id_base64url: String,
        /// 暗号化に使う受信者公開鍵（SEC1, Base64URL）
        #[arg(long)]
        public_key_base64url: String,
        /// 有効期限（秒, UNIX 時刻）
        #[arg(long)]
        expiration_sec: u64,
        /// 出力先ファイル（Base64URL 文字列）
        #[arg(long, default_value = "credential_bundle.b64")]
        output_file: PathBuf,
    },
    /// バンドルを復号して購読情報を取り出す
    Decode {
        /// バンドルを Base64URL で保存したファイル
        #[arg(long)]
        bundle_file: PathBuf,
        /// 鍵識別子（Base64URL, 8バイト）: バンドル先頭と一致することを確認
        #[arg(long)]
        key_id_base64url: String,
        /// 復号に使う受信者秘密鍵（SEC1, Base64URL）
        #[arg(long)]
        private_key_base64url: String,
        /// 書き出す購読 JSON ファイル
        #[arg(long, default_value = "subscription_from_bundle.json")]
        output_file: PathBuf,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Commands::Encode {
            subscription_file,
            key_id_base64url,
            public_key_base64url,
            expiration_sec,
            output_file,
        } => encode_cmd(
            subscription_file,
            key_id_base64url,
            public_key_base64url,
            expiration_sec,
            output_file,
        ),
        Commands::Decode {
            bundle_file,
            key_id_base64url,
            private_key_base64url,
            output_file,
        } => decode_cmd(
            bundle_file,
            key_id_base64url,
            private_key_base64url,
            output_file,
        ),
    }
}

fn encode_cmd(
    subscription_file: PathBuf,
    key_id_base64url: String,
    public_key_base64url: String,
    expiration_sec: u64,
    output_file: PathBuf,
) -> Result<()> {
    let raw = fs::read_to_string(&subscription_file)
        .with_context(|| format!("購読ファイルの読み込みに失敗: {}", subscription_file.display()))?;
    let subscription: 購読データ =
        serde_json::from_str(&raw).context("購読 JSON のパースに失敗")?;

    let key_id = base64::decode_config(&key_id_base64url, base64::URL_SAFE_NO_PAD)
        .context("鍵識別子の Base64URL デコードに失敗")?;
    if key_id.len() != 8 {
        bail!("鍵識別子は 8 バイトである必要があります");
    }

    let public_key = base64::decode_config(&public_key_base64url, base64::URL_SAFE_NO_PAD)
        .context("公開鍵の Base64URL デコードに失敗")?;

    let handle = CliEncodeHandle { key_id, public_key };
    let bundle = encode_credential_bundle(
        &subscription,
        &handle,
        expiration_sec,
        None,
    )?;

    let encoded = base64::encode_config(bundle, base64::URL_SAFE_NO_PAD);
    fs::write(&output_file, encoded)
        .with_context(|| format!("バンドルの書き込みに失敗: {}", output_file.display()))?;
    println!("バンドルを出力しました: {}", output_file.display());
    Ok(())
}

fn decode_cmd(
    bundle_file: PathBuf,
    key_id_base64url: String,
    private_key_base64url: String,
    output_file: PathBuf,
) -> Result<()> {
    let bundle_b64 = fs::read_to_string(&bundle_file)
        .with_context(|| format!("バンドルファイルの読み込みに失敗: {}", bundle_file.display()))?;
    let bundle = base64::decode_config(bundle_b64.trim(), base64::URL_SAFE_NO_PAD)
        .context("バンドルの Base64URL デコードに失敗")?;

    let expected_key_id = base64::decode_config(&key_id_base64url, base64::URL_SAFE_NO_PAD)
        .context("鍵識別子の Base64URL デコードに失敗")?;
    if expected_key_id.len() != 8 {
        bail!("鍵識別子は 8 バイトである必要があります");
    }
    if bundle.len() < 8 || &bundle[..8] != expected_key_id.as_slice() {
        bail!("バンドル先頭の鍵識別子が期待と一致しません");
    }

    let private_key_bytes = base64::decode_config(&private_key_base64url, base64::URL_SAFE_NO_PAD)
        .context("秘密鍵の Base64URL デコードに失敗")?;
    let secret = SecretKey::from_sec1_der(&private_key_bytes)
        .or_else(|_| SecretKey::from_sec1_pem(std::str::from_utf8(&private_key_bytes).unwrap_or("")))
        .or_else(|_| {
            if private_key_bytes.len() == 32 {
                let fb: &P256FieldBytes = P256FieldBytes::from_slice(&private_key_bytes);
                SecretKey::from_bytes(fb)
            } else {
                Err(p256::elliptic_curve::Error)
            }
        })
        .map_err(|_| anyhow::anyhow!("秘密鍵の読み込みに失敗しました"))?;

    let store = CliSingleKeyStore {
        expected_id: expected_key_id.clone(),
        secret,
        public: vec![],
    };

    let subscription = decode_credential_bundle(&bundle, &store)?;

    let json = serde_json::to_string_pretty(&subscription)
        .context("購読 JSON のシリアライズに失敗")?;
    fs::write(&output_file, json)
        .with_context(|| format!("購読データの書き込みに失敗: {}", output_file.display()))?;
    println!("購読データを出力しました: {}", output_file.display());
    Ok(())
}

struct CliEncodeHandle {
    key_id: Vec<u8>,
    public_key: Vec<u8>,
}

impl KeyHandle for CliEncodeHandle {
    fn key_identifier(&self) -> &[u8] {
        &self.key_id
    }
    fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }
    fn decrypt(&self, _ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        Err(anyhow::anyhow!("decode は非対応"))
    }
    fn sign(&self, _message: &[u8]) -> anyhow::Result<Vec<u8>> {
        Err(anyhow::anyhow!("署名は未実装です"))
    }
}

struct CliSingleKeyStore {
    expected_id: Vec<u8>,
    secret: SecretKey,
    public: Vec<u8>,
}

impl KeyStore for CliSingleKeyStore {
    fn lookup(&self, key_id: &[u8; 8]) -> anyhow::Result<Box<dyn KeyHandle>> {
        if self.expected_id.as_slice() != key_id {
            bail!("鍵IDが一致しません");
        }
        Ok(Box::new(CliDecodeHandle {
            key_id: self.expected_id.clone(),
            secret: self.secret.clone(),
            public: self.public.clone(),
        }))
    }
}

struct CliDecodeHandle {
    key_id: Vec<u8>,
    secret: SecretKey,
    public: Vec<u8>,
}

impl KeyHandle for CliDecodeHandle {
    fn key_identifier(&self) -> &[u8] {
        &self.key_id
    }
    fn public_key_bytes(&self) -> &[u8] {
        &self.public
    }
    fn decrypt(&self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        crypto::p256dhで復号(ciphertext, &self.secret)
    }
    fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        use p256::ecdsa::{signature::Signer, SigningKey};
        let signing: SigningKey = (&self.secret).into();
        let sig: p256::ecdsa::Signature = signing.sign(message);
        Ok(sig.to_bytes().to_vec())
    }
}
