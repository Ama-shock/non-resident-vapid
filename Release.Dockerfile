# Release / packaging 用のビルダー
FROM node:24-bookworm

ENV RUST_VERSION=1.91.0
ENV CARGO_HOME=/usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup
ENV PATH="/usr/local/cargo/bin:${PATH}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates pkg-config libssl-dev jq build-essential \
    && rm -rf /var/lib/apt/lists/*

# Rust ツールチェーンをインストール
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain ${RUST_VERSION}

RUN rustup target add wasm32-unknown-unknown
RUN cargo install wasm-bindgen-cli --version 0.2.92

WORKDIR /work

CMD ["bash"]
