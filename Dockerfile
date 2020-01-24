FROM golang

ADD src /go/src/dddns

RUN cd /go/src/dddns && \ 
    go build -o dddns && \
    cp dddns /usr/local/bin

ENTRYPOINT [ "dddns" ]