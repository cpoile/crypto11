#!/usr/bin/env bash
# Run in the pinned fixture image with the checkout mounted read-only at /source.
set -euo pipefail
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp -a /source/. "$work/source"
cd "$work/source"
python3 testdata/softhsm/prepare.py "$work/fixture"
export SOFTHSM2_CONF="$work/fixture/softhsm2.conf"
cp "$work/fixture/config.json" config
go mod download
gcc -shared -fPIC -pthread -I /usr/include/softhsm -o "$work/forward.so" testdata/softhsm/forward.c -ldl
export CRYPTO11_TEST_SHIM="$work/forward.so"
export CRYPTO11_TEST_MODULE=/usr/lib/softhsm/libsofthsm2.so
go version
gcc --version | head -1
dpkg-query -W softhsm2 libsofthsm2
# A dedicated run starts with no leaked contexts from older upstream tests.
go test -race -tags=crypto11_testshim -count=1 -timeout=120s -run '^(TestInvalidPinDoesntDestroyLibrary|TestNativeFailureOwnership|TestNativeAEADErrors)$' .
# Start the broad suite with a fresh store, independent of injected operations.
python3 testdata/softhsm/prepare.py "$work/full-fixture"
export SOFTHSM2_CONF="$work/full-fixture/softhsm2.conf"
cp "$work/full-fixture/config.json" config
go test -race -count=1 -timeout=10m ./...
