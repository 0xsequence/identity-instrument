#!/bin/sh

VERSION=${VERSION:-$(git describe --tags --abbrev=0)}
URL=${URL:-"https://dev-identity.sequence-dev.app/status"}
ENV=${ENV:-"dev"}

build_command="make VERSION=$VERSION ENV=$ENV eif"
build_output=$(eval $build_command 2>&1)

if [ $? -ne 0 ]; then
    echo "Build failed"
    exit 1
fi

boot_line=$(echo "$build_output" | grep "BootMeasurement: ")

build_pcr0=$(echo "$boot_line" | awk -F'"PCR0": "' '{print $2}' | awk -F'"' '{print $1}')
PCR0=${PCR0:-$build_pcr0}

go run github.com/0xsequence/tee-verifier/cmd/tee-verifier@latest \
    --pcr0 "$PCR0" \
    $URL
