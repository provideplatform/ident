FROM golang:1.13

RUN mkdir -p /go/src/github.com/provideapp
ADD . /go/src/github.com/provideapp/ident
WORKDIR /go/src/github.com/provideapp/ident

RUN make build

RUN go build -v -o ./bin/ident_api ./cmd/api
RUN go build -v -o ./bin/ident_consumer ./cmd/consumer
RUN go build -v -o ./bin/ident_migrate ./cmd/migrate
RUN ln -s ./bin/ident_api ident
RUN ln -s ./bin/ident_consumer ident_consumer
RUN ln -s ./bin/ident_migrate ident_migrate

EXPOSE 8080
ENTRYPOINT ["./ident"]
