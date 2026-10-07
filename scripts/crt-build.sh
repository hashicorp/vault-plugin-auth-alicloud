#!/usr/bin/env bash
# Copyright IBM Corp. 2018, 2025
# SPDX-License-Identifier: MPL-2.0

# The crt-build script is used to create vault-plugin-auth-alicloud release
# builds. It is invoked by hashicorp/actions-go-build in .github/workflows/build.yml.

set -euo pipefail

# We don't want to get stuck in some kind of interactive pager
export GIT_PAGER=cat

TOOL=vault-plugin-auth-alicloud

# Get the build date from the latest commit since it can be used across all builds
function build_date() {
  : "${DATE_FORMAT:="%Y-%m-%dT%H:%M:%SZ"}"
  git show --no-show-signature -s --format=%cd --date=format:"$DATE_FORMAT" HEAD
}

# Get the revision, which is the latest commit SHA
function build_revision() {
  git rev-parse HEAD
}

# Build vault-plugin-auth-alicloud
function build() {
  local revision
  local ldflags

  revision=$(build_revision)
  : "${BIN_PATH:="dist/${TOOL}"}" # set explicitly when not run by actions-go-build
  : "${GO_TAGS:=""}"
  : "${KEEP_SYMBOLS:=""}"

  # Strip the symbol and dwarf information by default
  if [ -n "$KEEP_SYMBOLS" ]; then
    ldflags=""
  else
    ldflags="-s -w"
  fi

  echo "--> Building ${TOOL} revision ${revision}, built $(build_date)"
  CGO_ENABLED=0 go build -o "$BIN_PATH" -tags "$GO_TAGS" -ldflags "$ldflags" -trimpath -buildvcs=false "./cmd/${TOOL}"
}

function main() {
  case ${1:-} in
  build)
    build
  ;;
  date)
    build_date
  ;;
  revision)
    build_revision
  ;;
  *)
    echo "unknown sub-command" >&2
    exit 1
  ;;
  esac
}

main "$@"
