FROM golang:1.13

RUN mkdir -p /go/src/github.com/provideapp
ADD . /go/src/github.com/provideapp/ident
WORKDIR /go/src/github.com/provideapp/ident

RUN make build

EXPOSE 8080
ENTRYPOINT ["./ops/run_api.sh"]
