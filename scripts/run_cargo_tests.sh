#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates

export CARGO_TERM_COLOR=always
cargo test
