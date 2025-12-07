# Headless Chrome（Xvfb）と Puppeteer を使った E2E 用 Push 購読・送信フィクスチャ
FROM rust:1.91-slim-bookworm AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml ./
COPY src ./src
COPY README.md ./
RUN rustup target add wasm32-unknown-unknown
RUN cargo install wasm-bindgen-cli --version 0.2.92
RUN cargo build --release
RUN cargo build --release --target wasm32-unknown-unknown --lib
RUN wasm-bindgen --target web --out-dir /app/pkg /app/target/wasm32-unknown-unknown/release/non_resident_vapid.wasm

FROM node:24-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends chromium xvfb xauth ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV CHROME_BIN=/usr/bin/chromium \
    PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true \
    DBUS_SESSION_BUS_ADDRESS=/dev/null

WORKDIR /e2e

COPY e2e/package*.json ./
RUN npm ci --omit=dev

COPY e2e/get_push_params.js ./get_push_params.js
COPY e2e/send_push.sh ./send_push.sh
COPY e2e/run_all.sh ./run_all.sh
COPY e2e/app.js ./app.js
COPY e2e/sw.js ./sw.js
COPY --from=builder /app/target/release/credential-bundle-cli /usr/local/bin/credential-bundle-cli
COPY --from=builder /app/target/release/bundle-server /usr/local/bin/bundle-server
COPY --from=builder /app/pkg /e2e/pkg

RUN chmod +x /e2e/send_push.sh /e2e/run_all.sh

CMD ["/e2e/run_all.sh"]
