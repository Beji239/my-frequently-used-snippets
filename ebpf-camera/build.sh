#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/camera.bpf.c"
OUT="$HERE/camera.bpf.o"
TMP="$HERE/.build"
mkdir -p "$TMP"

if [[ ! -s "$TMP/vmlinux.h" ]]; then
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$TMP/vmlinux.h"
fi

case "$(uname -m)" in
    x86_64|i?86)     BPF_ARCH=x86 ;;
    aarch64|arm64)   BPF_ARCH=arm64 ;;
    arm*)            BPF_ARCH=arm ;;
    riscv64)         BPF_ARCH=riscv ;;
    *) echo "No BPF target for $(uname -m)"; exit 1 ;;
esac

clang -target bpf -D__TARGET_ARCH_$BPF_ARCH -g -O2 -Wall \
    -I "$TMP" -c "$SRC" -o "$OUT"
echo "Built $OUT"
