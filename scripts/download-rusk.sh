#!/usr/bin/env bash

set -e

TARGET_DIR="target"

if [ -f "${TARGET_DIR}/rusk/rusk" ]; then
    echo "✅ Rusk binary already exists at ${TARGET_DIR}/rusk/rusk"
    exit 0
fi

# Detect OS
case "$(uname -s)" in
    Linux*)
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            if [ "$ID" = "ubuntu" ] && [ "${VERSION_ID}" = "22.04" ]; then
                OS="ubuntu22"
            else
                OS="linux"
            fi
        else
            OS="linux"
        fi
        ;;
    Darwin*)
        OS="macos"
        ;;
    *)
        echo "❌ Unsupported OS: $(uname -s)"
        exit 1
        ;;
esac

# Detect architecture
case "$(uname -m)" in
    x86_64|amd64)
        ARCH="x64"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        ;;
    *)
        echo "❌ Unsupported architecture: $(uname -m)"
        exit 1
        ;;
esac

echo "✅ Detected: $OS-$ARCH"

# Get latest release
LATEST_TAG=$(curl -s "https://api.github.com/repos/dusk-network/rusk/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
VERSION=${LATEST_TAG#dusk-rusk-}

echo "📦 Latest version: $VERSION"

# Download and extract
FILENAME="rusk-${VERSION}-${OS}-${ARCH}-default.tar.gz"
DOWNLOAD_URL="https://github.com/dusk-network/rusk/releases/download/${LATEST_TAG}/${FILENAME}"

mkdir -p "$TARGET_DIR"

echo "⬇️  Downloading: $FILENAME"
curl -L -o "${TARGET_DIR}/${FILENAME}" "$DOWNLOAD_URL"

echo "📂 Extracting to ${TARGET_DIR}..."
mkdir -p "${TARGET_DIR}/rusk"
tar -xzf "${TARGET_DIR}/${FILENAME}" -C "${TARGET_DIR}/rusk" --strip-components=1

rm "${TARGET_DIR}/${FILENAME}"
echo "✅ Done! Files extracted to ${TARGET_DIR}/"
