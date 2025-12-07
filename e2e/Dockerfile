# Headless Chrome（Xvfb）と Puppeteer を使った E2E 用 Push 購読・送信フィクスチャ
FROM rust:1.91-slim-bookworm AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml ./
COPY src ./src
COPY README.md ./
RUN cargo build --release

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
COPY --from=builder /app/target/release/non-resident-vapid /usr/local/bin/non-resident-vapid

RUN chmod +x /e2e/send_push.sh /e2e/run_all.sh

CMD ["/e2e/run_all.sh"]
