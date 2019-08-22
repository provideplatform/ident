FROM golang:1.11

RUN mkdir -p /go/src/github.com/provideapp
ADD . /go/src/github.com/provideapp/ident
WORKDIR /go/src/github.com/provideapp/ident

RUN curl https://glide.sh/get | sh
RUN glide install

RUN go build -v -o ./bin/ident_api ./cmd/api
RUN go build -v -o ./bin/ident_consumer ./cmd/consumer
RUN go build -v -o ./bin/ident_migrate ./cmd/migrate
RUN ln -s ./bin/ident_api goldmine
RUN ln -s ./bin/ident_consumer goldmine_consumer
RUN ln -s ./bin/ident_migrate goldmine_migrate

EXPOSE 8080
ENTRYPOINT ["./ident"]
