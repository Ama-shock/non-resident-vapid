#!/usr/bin/env bash
set -euo pipefail

購読ファイル="/data/subscription.json"
鍵ファイル="/data/vapid_keys.json"

while [ ! -f "$購読ファイル" ] || [ ! -f "$鍵ファイル" ]; do
  echo "[push-sender] 購読情報と鍵の生成を待機中..."
  sleep 2
done

exec non-resident-vapid \
  --subscription-file "$購読ファイル" \
  --vapid-keys-file "$鍵ファイル" \
  --payload "e2e送信テスト" \
  --subject "mailto:test@example.com" \
  --ttl 60
