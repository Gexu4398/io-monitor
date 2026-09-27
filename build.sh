#!/usr/bin/env bash
# 构建镜像 -> 导出 tar 到 deploy/images -> 删除本地镜像
set -euo pipefail

IMAGE_NAME="iomon"
IMAGE_TAG="latest"
IMAGE="${IMAGE_NAME}:${IMAGE_TAG}"
OUT_DIR="$(cd "$(dirname "$0")" && pwd)/deploy/images"
TAR_DATE="${OUT_DIR}/${IMAGE_NAME}-$(date +%Y%m%d).tar"
TAR_LATEST="${OUT_DIR}/${IMAGE_NAME}-latest.tar"

echo "==> 构建镜像 ${IMAGE}"
docker compose build

echo "==> 导出镜像到 ${TAR_DATE}"
mkdir -p "${OUT_DIR}"
docker save "${IMAGE}" -o "${TAR_DATE}"

# 同步一份 latest，部署侧固定加载这个名字即可
cp -f "${TAR_DATE}" "${TAR_LATEST}"

echo "==> 删除本地镜像 ${IMAGE}"
docker rmi "${IMAGE}"

echo "==> 完成: ${TAR_DATE}"
