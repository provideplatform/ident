#!/bin/sh

pushd "$GOPATH/src/github.com/nats-io/nats-streaming-server"
go run nats-streaming-server.go --cid provide --auth localauthtoken
popd
