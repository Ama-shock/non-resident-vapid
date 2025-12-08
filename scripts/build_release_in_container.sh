#!/usr/bin/env bash
set -euo pipefail

# Rust/wasm/npm のビルドを docker compose の release-build サービス内で完結させ、成果物を dist/ に集約するスクリプト。

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[release] docker compose run release-build を実行します"
docker compose run --rm release-build bash /work/scripts/release_build_inner.sh

echo "[release] 完了: dist/ に成果物を出力しました (ホスト側 dist/ を参照してください)"
