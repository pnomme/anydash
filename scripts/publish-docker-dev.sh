#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

DOCKER_USERNAME="${DOCKER_USERNAME:-anycloudas}"
IMAGE_NAME="${IMAGE_NAME:-anydash}"
BUILDER_NAME="${BUILDER_NAME:-anydash-builder}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"
BASE_VERSION=$(node -e "try { console.log(require('fs').readFileSync('VERSION', 'utf8').trim()) } catch { console.log('0.0.0') }")
CUSTOM_NAME="${1:-}"
VERSION="${BASE_VERSION}-dev-${CUSTOM_NAME}"

if [ -z "$CUSTOM_NAME" ]; then
  echo "ERROR: Custom name is required!"
  echo "Usage: $0 <custom-name>"
  exit 1
fi
if ! echo "$CUSTOM_NAME" | grep -Eq '^[a-zA-Z0-9][a-zA-Z0-9_.-]*$'; then
  echo "ERROR: Custom name must be a valid Docker tag suffix."
  echo "Use letters, numbers, dots, underscores, or dashes."
  exit 1
fi

echo "AnyDash Custom Dev Release"
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
  --file backend/Dockerfile \
  --push \
  backend/

echo "Backend image pushed successfully."

echo "Building and pushing frontend image..."
docker buildx build \
  --platform "$PLATFORMS" \
  --tag "$DOCKER_USERNAME/$IMAGE_NAME-frontend:$VERSION" \
  --build-arg VITE_APP_VERSION="$VERSION" \
  --build-arg VITE_APP_BUILD_LABEL="development" \
  --file frontend/Dockerfile \
  --push \
  .

echo "Frontend image pushed successfully."
echo "Published:"
echo "  $DOCKER_USERNAME/$IMAGE_NAME-backend:$VERSION"
echo "  $DOCKER_USERNAME/$IMAGE_NAME-frontend:$VERSION"
