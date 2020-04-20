FROM golang

ADD ./ /go/src/dddns

RUN cd /go/src/dddns && \ 
    go build ./cmd/dddns/dddns.go && \
    cp dddns /usr/local/bin && \
    chmod +x /usr/local/bin/dddns

ENTRYPOINT [ "dddns","daemon","--dnsenable" ]