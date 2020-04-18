FROM golang

ADD ./ /go/src/dddns

RUN cd /go/src/dddns && \ 
    go build -o dddnscli ./cli/cli.go && \
    cp dddnscli /usr/bin
RUN chmod +x /usr/bin/dddnscli

ENTRYPOINT [ "/usr/bin/dddnscli","daemon","--dnsenable" ]