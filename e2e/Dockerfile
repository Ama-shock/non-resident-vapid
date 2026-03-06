# Headless Chrome（Puppeteer）を使った E2E 用 Push 購読・送信フィクスチャ
FROM rust:1.91-slim-bookworm AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml ./
COPY Cargo.lock ./
COPY src ./src
COPY README.md ./
RUN rustup target add wasm32-unknown-unknown
RUN cargo install wasm-bindgen-cli --version 0.2.106
RUN cargo build --release
RUN cargo build --release --target wasm32-unknown-unknown --lib --no-default-features
RUN wasm-bindgen --target web --out-dir /app/pkg /app/target/wasm32-unknown-unknown/release/non_resident_vapid.wasm

FROM node:24-bookworm
# Chrome の実行に必要なシステム依存ライブラリ
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        fonts-liberation \
        libasound2 \
        libatk-bridge2.0-0 \
        libatk1.0-0 \
        libcairo2 \
        libcups2 \
        libdbus-1-3 \
        libexpat1 \
        libfontconfig1 \
        libgbm1 \
        libglib2.0-0 \
        libgtk-3-0 \
        libnspr4 \
        libnss3 \
        libpango-1.0-0 \
        libstdc++6 \
        libx11-6 \
        libx11-xcb1 \
        libxcb1 \
        libxcomposite1 \
        libxcursor1 \
        libxdamage1 \
        libxext6 \
        libxfixes3 \
        libxi6 \
        libxrandr2 \
        libxrender1 \
        libxtst6 \
        wget \
        xdg-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /e2e

COPY e2e/package.json ./
# puppeteer の npm install で Chrome を自動ダウンロードする
ENV PUPPETEER_CACHE_DIR=/root/.cache/puppeteer
RUN npm install --omit=dev

COPY e2e/get_push_params_puppeteer.js ./get_push_params.js
COPY e2e/send_push.sh ./send_push.sh
COPY e2e/run_all.sh ./run_all.sh
COPY e2e/app.js ./app.js
COPY e2e/sw.js ./sw.js
COPY --from=builder /app/target/release/credential_bundle_cli /usr/local/bin/credential-bundle-cli
COPY --from=builder /app/target/release/bundle_server_cli /usr/local/bin/bundle-server-cli
COPY --from=builder /app/pkg /e2e/pkg

RUN chmod +x /e2e/send_push.sh /e2e/run_all.sh

CMD ["/e2e/run_all.sh"]
