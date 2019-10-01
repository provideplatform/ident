#!/bin/bash

revision=$(git rev-parse --short=7 --verify HEAD)

GOOS=darwin GOARCH=amd64 go build -v -o "./.bin/sia_consumer.${revision}.darwin-amd64" ./cmd/sia_consumer
GOOS=linux GOARCH=amd64 go build -v -o "./.bin/sia_consumer.${revision}.linux-amd64" ./cmd/sia_consumer
