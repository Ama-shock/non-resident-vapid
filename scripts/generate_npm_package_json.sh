#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCOPE="${NPM_SCOPE:-@ama-shock}"
OUT="${ROOT}/package.json"

cd "${ROOT}"
mkdir -p "${ROOT}"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq が見つかりません。コンテナ内で実行するか jq をインストールしてください。" >&2
  exit 1
fi

META="$(cargo metadata --no-deps --format-version 1)"
PKG="$(echo "${META}" | jq '.packages[0]')"

NAME="$(echo "${PKG}" | jq -r '.name')"
VERSION="$(echo "${PKG}" | jq -r '.version')"
DESCRIPTION="$(echo "${PKG}" | jq -r '.description // ""')"
REPO="$(echo "${PKG}" | jq -r '.repository // ""')"
LICENSE="$(echo "${PKG}" | jq -r '.license // ""')"
KEYWORDS_JSON="$(echo "${PKG}" | jq '.keywords // []')"

NPM_NAME="${SCOPE}/${NAME}"

jq -n \
  --arg name "${NPM_NAME}" \
  --arg version "${VERSION}" \
  --arg description "${DESCRIPTION}" \
  --arg repo "${REPO}" \
  --arg license "${LICENSE}" \
  --argjson keywords "${KEYWORDS_JSON}" \
  '{
    name: $name,
    version: $version,
    description: $description,
    main: "./pkg/non_resident_vapid.js",
    module: "./pkg/non_resident_vapid.js",
    types: "./pkg/non_resident_vapid.d.ts",
    sideEffects: false,
    files: ["pkg/"],
    repository: { type: "git", url: $repo },
    license: $license,
    keywords: $keywords
  }' > "${OUT}"

echo "[generate-npm] package.json を生成しました (${OUT})"
