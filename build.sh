#!/usr/bin/env bash
# 构建「脚本定时任务」fpk: 需要 Go 与 fnpack
# 可用环境变量覆盖工具路径: GO=... FNPACK=...
set -euo pipefail
cd "$(dirname "$0")"
GO=${GO:-go}
FNPACK=${FNPACK:-fnpack}
mkdir -p package/app/bin
(cd src && CGO_ENABLED=0 "$GO" build -trimpath -o ../package/app/bin/script-tasks .)
(cd package && TAR_OPTIONS="--no-same-owner" "$FNPACK" build)
cp package/script-tasks.fpk ./script-tasks.fpk
echo "done: script-tasks.fpk"
