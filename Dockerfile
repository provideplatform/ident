FROM golang:1.11

RUN mkdir -p /go/src/github.com/provideapp
ADD . /go/src/github.com/provideapp/ident
WORKDIR /go/src/github.com/provideapp/ident

RUN curl https://glide.sh/get | sh
RUN glide install
RUN go build

EXPOSE 8080
CMD ["./ident"]
