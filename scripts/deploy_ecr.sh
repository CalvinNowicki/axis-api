#!/usr/bin/env bash
set -euo pipefail

export AWS_PAGER=""

PROFILE="${PROFILE:-axis-stg}"
REGION="${REGION:-us-west-2}"
ACCOUNT_ID="${ACCOUNT_ID:-148761682818}"
REPO="${REPO:-axis-api}"

TAG="$(git rev-parse --short HEAD)"
IMAGE_URI="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${REPO}"

aws ecr get-login-password --profile "$PROFILE" --region "$REGION" \
  | docker login --username AWS --password-stdin "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"

docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t "${IMAGE_URI}:${TAG}" \
  --push \
  .

echo "${IMAGE_URI}:${TAG}"
