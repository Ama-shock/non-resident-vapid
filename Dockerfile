# ベースイメージ: Rust ツールチェーン入りの Debian bookworm Slim
FROM rust:1.91-slim-bookworm AS builder

# ビルド・テストで要求される最低限の依存
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# マニフェストとソースを配置
COPY Cargo.toml ./
COPY src ./src
COPY README.md ./

# 依存解決を実行（ソースが存在する状態で行う）
RUN cargo fetch

# コンテナ内でビルドとテストを完了させる
RUN cargo build --release
RUN cargo test --release

# 実行用の軽量イメージ
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/non-resident-vapid /usr/local/bin/non-resident-vapid

CMD ["non-resident-vapid"]
