FROM golang:1.15 AS builder

RUN mkdir -p /go/src/github.com/provideapp
ADD . /go/src/github.com/provideapp/ident
WORKDIR /go/src/github.com/provideapp/ident

RUN make build

FROM golang:1.15

RUN mkdir -p /ident
WORKDIR /ident

COPY --from=builder /go/src/github.com/provideapp/ident/.bin /ident/.bin
COPY --from=builder /go/src/github.com/provideapp/ident/ops /ident/ops

EXPOSE 8080
ENTRYPOINT ["./ops/run_api.sh"]
