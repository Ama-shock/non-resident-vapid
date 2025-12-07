use anyhow::Result;

/// 鍵操作ハンドル: 公開鍵提供、バンドル復号、VAPID 署名を担う。
pub trait KeyHandle: Send + Sync {
    /// バンドルに埋め込まれる鍵識別子（8 バイト固定）
    fn key_identifier(&self) -> &[u8];
    /// 公開鍵（圧縮 SEC1 形式想定）
    fn public_key_bytes(&self) -> &[u8];
    /// 暗号化済みデータの復号（用途非依存）
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
    /// 任意データに署名し、署名結果を返す（鍵素材は実装側で管理）
    /// 返却値は ES256 の R||S 連結 64 バイト生データとする
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;
}

/// 鍵ハンドルストア: 8 ビット ID から鍵ハンドルを取得する。
pub trait KeyStore: Send + Sync {
    /// 8 バイト固定の鍵識別子に対応する鍵ハンドルを返す。
    fn lookup(&self, key_id: &[u8; 8]) -> Result<Box<dyn KeyHandle>>;
}
