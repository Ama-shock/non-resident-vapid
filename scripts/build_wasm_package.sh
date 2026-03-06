#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${ROOT}/target/wasm32-unknown-unknown/release"
PKG_DIR="${ROOT}/pkg"

echo "[build-wasm] package.json を生成します (Cargo.toml から取得)"
bash "${ROOT}/scripts/generate_npm_package_json.sh"

echo "[build-wasm] ターゲット wasm32-unknown-unknown をビルドします"
cargo build --release --target wasm32-unknown-unknown --lib --no-default-features

echo "[build-wasm] wasm-bindgen で pkg へ出力します"
mkdir -p "${PKG_DIR}"
wasm-bindgen --target bundler --out-dir "${PKG_DIR}" "${TARGET_DIR}/non_resident_vapid.wasm"

echo "[build-wasm] 完了: ${PKG_DIR} に出力しました"
