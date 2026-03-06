use serde::{Deserialize, Serialize};
#[cfg(feature = "server")]
use web_push::SubscriptionInfo;

/// Push 購読データ（Base64URL 文字列のまま保持）
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct 購読データ {
    pub endpoint: String,
    pub auth: String,
    pub p256dh: String,
    #[serde(rename = "expirationTime")]
    pub expiration_time: Option<serde_json::Value>,
}

#[cfg(feature = "server")]
impl From<購読データ> for SubscriptionInfo {
    fn from(value: 購読データ) -> Self {
        SubscriptionInfo::new(&value.endpoint, &value.p256dh, &value.auth)
    }
}

#[cfg(feature = "server")]
impl From<&購読データ> for SubscriptionInfo {
    fn from(value: &購読データ) -> Self {
        SubscriptionInfo::new(&value.endpoint, &value.p256dh, &value.auth)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn シリアライズとデシリアライズができる() {
        let data = 購読データ {
            endpoint: "https://example.test".into(),
            auth: "YWJj".into(),
            p256dh: "ZGVm".into(),
            expiration_time: Some(serde_json::Value::from(123u64)),
        };
        let json = serde_json::to_string(&data).unwrap();
        let back: 購読データ = serde_json::from_str(&json).unwrap();
        assert_eq!(data, back);
    }
}
