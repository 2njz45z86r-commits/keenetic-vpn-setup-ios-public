#!/usr/bin/env bash
set -euo pipefail
ios="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$ios/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mobile_version="v0.0.0-20261117202452-47699113848a"
mkdir -p "$work/module" "$work/bin" "$ios/Frameworks"
cp "$root/go.mod" "$work/module/"
if [ -f "$root/go.sum" ]; then cp "$root/go.sum" "$work/module/"; fi
cp -R "$root/core" "$root/mobile" "$work/module/"
export GOBIN="$work/bin"
export PATH="$GOBIN:$PATH"
cd "$work/module"
go install "golang.org/x/mobile/cmd/gomobile@$mobile_version"
go install "golang.org/x/mobile/cmd/gobind@$mobile_version"
go get "golang.org/x/mobile/bind@$mobile_version"
gomobile init
gomobile bind -target=ios,iossimulator -iosversion=15.0 -o "$ios/Frameworks/Mobile.xcframework" ./mobile
cd "$ios"
xcodegen generate --spec project.yml
