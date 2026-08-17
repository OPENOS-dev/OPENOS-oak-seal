#!/usr/bin/env bash
# 构建 openos-oak-seal (优先静态链接 OpenSSL; 失败回退动态)
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if cc -O2 -static -o "$DIR/openos-oak-seal" \
     "$DIR/openos-oak-seal.c" -lssl -lcrypto 2>/dev/null; then
    echo "已构建 (静态): $DIR/openos-oak-seal"
else
    cc -O2 -o "$DIR/openos-oak-seal" "$DIR/openos-oak-seal.c" -lssl -lcrypto
    echo "已构建 (动态): $DIR/openos-oak-seal"
fi
