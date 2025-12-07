#!/usr/bin/env bash
set -euo pipefail

export DISPLAY=:99
Xvfb :99 -screen 0 1280x720x24 &

exec npm run get-push-params
