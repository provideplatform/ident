#!/bin/bash

rm ident
go fmt
go build .
NATS_TOKEN=localauthtoken \
	NATS_STREAMING_URL=nats://localhost:4222 \
	NATS_STREAMING_CONCURRENCY=2 \
	NATS_CLUSTER_ID=provide \
	NATS_CLIENT_PREFIX=ident \
	GIN_MODE=debug \
	DATABASE_NAME=ident \
	DATABASE_USER=ident \
	DATABASE_PASSWORD=ident \
	DATABASE_HOST=localhost \
	LOG_LEVEL=DEBUG \
	PORT=8081 \
	./ident
