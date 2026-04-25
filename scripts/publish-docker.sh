#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

DOCKER_USERNAME="${DOCKER_USERNAME:-anycloudas}"
IMAGE_NAME="${IMAGE_NAME:-anydash}"
BUILDER_NAME="${BUILDER_NAME:-anydash-builder}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"
VERSION=${1:-$(node -e "try { console.log(require('fs').readFileSync('VERSION', 'utf8').trim()) } catch { console.log('latest') }")}

CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
ALLOWED_BRANCH="${ALLOWED_BRANCH:-main}"
if [ "${SKIP_BRANCH_CHECK:-false}" != "true" ] && [ "$CURRENT_BRANCH" != "$ALLOWED_BRANCH" ]; then
  echo "ERROR: This script can only be run on the '$ALLOWED_BRANCH' branch."
  echo "Current branch: '$CURRENT_BRANCH'"
  echo "Set SKIP_BRANCH_CHECK=true to publish from this branch anyway."
  exit 1
fi

echo "AnyDash Docker Builder"
echo "Docker Hub namespace: $DOCKER_USERNAME"
echo "Image base name:      $IMAGE_NAME"
echo "Version tag:          $VERSION"
echo "Platforms:            $PLATFORMS"

echo "Checking Docker Hub authentication..."
if ! docker info | grep -q "Username: $DOCKER_USERNAME"; then
  echo "Not logged in. Please login to Docker Hub:"
  docker login -u "$DOCKER_USERNAME"
else
  echo "Already logged in as $DOCKER_USERNAME."
fi

echo "Setting up buildx builder..."
if ! docker buildx inspect "$BUILDER_NAME" > /dev/null 2>&1; then
  echo "Creating new buildx builder..."
  docker buildx create --name "$BUILDER_NAME" --use --bootstrap
else
  echo "Using existing buildx builder."
  docker buildx use "$BUILDER_NAME"
fi

echo "Building and pushing backend image..."
docker buildx build \
  --platform "$PLATFORMS" \
  --tag "$DOCKER_USERNAME/$IMAGE_NAME-backend:$VERSION" \
  --tag "$DOCKER_USERNAME/$IMAGE_NAME-backend:latest" \
  --file backend/Dockerfile \
  --push \
  backend/

echo "Backend image pushed successfully."

echo "Building and pushing frontend image..."
docker buildx build \
  --platform "$PLATFORMS" \
  --tag "$DOCKER_USERNAME/$IMAGE_NAME-frontend:$VERSION" \
  --tag "$DOCKER_USERNAME/$IMAGE_NAME-frontend:latest" \
  --build-arg VITE_APP_VERSION="$VERSION" \
  --build-arg VITE_APP_BUILD_LABEL="production" \
  --file frontend/Dockerfile \
  --push \
  .

echo "Frontend image pushed successfully."
echo "Published:"
echo "  $DOCKER_USERNAME/$IMAGE_NAME-backend:$VERSION"
echo "  $DOCKER_USERNAME/$IMAGE_NAME-backend:latest"
echo "  $DOCKER_USERNAME/$IMAGE_NAME-frontend:$VERSION"
echo "  $DOCKER_USERNAME/$IMAGE_NAME-frontend:latest"
