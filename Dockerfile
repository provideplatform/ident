FROM golang

RUN apt-get update && apt-get install -y ca-certificates git-core ssh

ADD .gocore-id_rsa /root/.ssh/id_rsa
RUN chmod 600 /root/.ssh/id_rsa
RUN echo "Host github.com\n\tStrictHostKeyChecking no\n" >> /root/.ssh/config
RUN git config --global url.ssh://git@github.com/.insteadOf https://github.com/

RUN mkdir -p /go/src/github.com/provideapp
ADD . /go/src/github.com/provideapp/ident
WORKDIR /go/src/github.com/provideapp/ident
RUN go-wrapper download
RUN go-wrapper install

EXPOSE 8080
CMD ["go-wrapper", "run"]
