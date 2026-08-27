#!/usr/bin/env bash
#
# 构建发布用的双架构二进制。
#
# 存在理由（v0.13.21 事故）：手工敲 go build 漏掉 -X main.version，
# 产物自报 "dev"，升级事务脚本的 version_ok 校验必然失败，用户端表现为
# 「升级失败，已自动回退」。版本注入不能依赖人记得，必须固化在脚本里，
# 并在产出后自检——构建成功但版本错的产物比构建失败更危险。
#
# 用法：scripts/build-release.sh v0.13.21

set -euo pipefail

TAG="${1:-}"
if [ -z "$TAG" ]; then
  echo "用法: $0 <tag>   例如: $0 v0.13.21" >&2
  exit 1
fi
case "$TAG" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "错误: tag 必须形如 v1.2.3，收到 '$TAG'" >&2; exit 1 ;;
esac

cd "$(dirname "$0")/.."
OUT=dist
mkdir -p "$OUT"

for arch in amd64 arm64; do
  echo "==> 构建 linux/$arch"
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
    go build -trimpath -ldflags="-s -w -X main.version=${TAG}" \
    -o "${OUT}/5gpnd-linux-${arch}" ./cmd/5gpnd
done

# 自检：产物必须自报正确版本，否则升级事务会判定失败并回退。
# 只能检查本机架构；交叉架构靠同一条 ldflags 保证一致。
HOST_ARCH=$(go env GOHOSTARCH)
BIN="${OUT}/5gpnd-linux-${HOST_ARCH}"
if [ -x "$BIN" ]; then
  GOT=$("$BIN" version)
  WANT="5gpn-next ${TAG}"
  if [ "$GOT" != "$WANT" ]; then
    echo "错误: 版本自检失败" >&2
    echo "  期望: $WANT" >&2
    echo "  实际: $GOT" >&2
    echo "  （升级事务的 version_ok 会因此判定失败并自动回退）" >&2
    exit 1
  fi
  echo "==> 版本自检通过: $GOT"
else
  echo "警告: 本机架构 ${HOST_ARCH} 无对应产物，跳过版本自检" >&2
fi

( cd "$OUT" && sha256sum 5gpnd-linux-amd64 5gpnd-linux-arm64 > SHA256SUMS )
echo "==> SHA256SUMS"
cat "${OUT}/SHA256SUMS"
