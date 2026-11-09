#!/usr/bin/env bash
set -euo pipefail

source /Users/kangchen/claude/usbdrive/go-sdk/env.sh
cd "$(dirname "$0")/.."

go vet ./...
go test ./...

APP=dist/Tools/VaultLock.app
rm -rf dist/Tools
mkdir -p dist/Tools "$APP/Contents/MacOS"

GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -H windowsgui" -o dist/Tools/VaultLock.exe ./cmd/vaultlock
# Gio's macOS backend uses cgo (clang from the Xcode Command Line Tools).
GOOS=darwin  GOARCH=arm64 CGO_ENABLED=1 go build -trimpath -ldflags "-s -w" -o build/VaultLock-arm64 ./cmd/vaultlock
GOOS=darwin  GOARCH=amd64 CGO_ENABLED=1 go build -trimpath -ldflags "-s -w" -o build/VaultLock-amd64 ./cmd/vaultlock
lipo -create -output "$APP/Contents/MacOS/VaultLock" build/VaultLock-arm64 build/VaultLock-amd64
cp build/Info.plist "$APP/Contents/Info.plist"
chmod +x "$APP/Contents/MacOS/VaultLock"

ls -l dist/Tools/VaultLock.exe "$APP/Contents/MacOS/VaultLock" | awk '{print $5, $9}'
