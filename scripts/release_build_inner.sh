#!/usr/bin/env bash
set -euo pipefail

ROOT="/work"
DIST="${ROOT}/dist"
TARGET_DIR="${ROOT}/target/wasm32-unknown-unknown/release"
PKG_DIR="${ROOT}/pkg"

mkdir -p "${DIST}"

echo "[release-inner] package.json を生成します"
bash "${ROOT}/scripts/generate_npm_package_json.sh"

echo "[release-inner] wasm ビルドを実行します"
cargo build --release --target wasm32-unknown-unknown --lib
mkdir -p "${PKG_DIR}"
wasm-bindgen --target bundler --out-dir "${PKG_DIR}" "${TARGET_DIR}/non_resident_vapid.wasm"

echo "[release-inner] crate をパッケージングします"
cargo package --allow-dirty --no-verify
CRATE_PATH=$(ls "${ROOT}/target/package"/non-resident-vapid-*.crate | tail -n1)
cp "${CRATE_PATH}" "${DIST}/"
echo "[release-inner] .crate を dist/ にコピー: $(basename "${CRATE_PATH}")"

echo "[release-inner] npm pack を実行します"
npm pack --pack-destination "${DIST}"

echo "[release-inner] 完了: dist/ に成果物を出力しました"
