#!/bin/sh
SDK_PATH=$(xcrun --sdk iphoneos --show-sdk-path)
CLANG=$(xcrun --sdk iphoneos --find clang)
exec "$CLANG" -isysroot "$SDK_PATH" -arch arm64 -mios-version-min=15.0 "$@"
