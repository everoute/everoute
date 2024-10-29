FROM golang:1.20 as builder

# Download deps
RUN mkdir -p $GOPATH/src/everoute/bin
RUN mkdir -p $GOPATH/src/everoute/tests/e2e/tools
WORKDIR $GOPATH/src/everoute

RUN mkdir -p /opt/everoute/bin

COPY ./tests/e2e/tools $GOPATH/src/everoute/tests/e2e/tools
COPY ./go.mod $GOPATH/src/everoute/go.mod
COPY ./go.sum $GOPATH/src/everoute/go.sum

# Build
RUN CGO_ENABLED=0 go build -o bin/net-utils tests/e2e/tools/net-utils/*.go

RUN cp $GOPATH/src/everoute/bin/* /opt/everoute/bin/
RUN chmod 755 /opt/everoute/bin/*

#FROM ubuntu
FROM ubuntu:22.04
ARG TARGETOS
ARG TARGETARCH
RUN echo "platform $TARGETOS $TARGETARCH"

RUN mkdir -p /opt/everoute/bin
COPY --from=builder /opt/everoute/bin/* /opt/everoute/bin/

WORKDIR /opt/everoute/bin
ENV PATH=${PATH}:/opt/everoute/bin
