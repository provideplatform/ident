FROM golang:1.15 AS builder

RUN mkdir -p /go/src/github.com/provideplatform
ADD . /go/src/github.com/provideplatform/ident
WORKDIR /go/src/github.com/provideplatform/ident

RUN make build

FROM alpine

RUN apk add --no-cache bash curl libc6-compat

RUN mkdir -p /ident
WORKDIR /ident

COPY --from=builder /go/src/github.com/provideplatform/ident/.bin /ident/.bin
COPY --from=builder /go/src/github.com/provideplatform/ident/ops /ident/ops

EXPOSE 8080
ENTRYPOINT ["./ops/run_api.sh"]
