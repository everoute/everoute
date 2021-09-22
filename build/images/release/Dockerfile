FROM golang:1.15 as builder

# Download deps
RUN mkdir -p $GOPATH/src/everoute
WORKDIR $GOPATH/src/everoute

COPY go.mod go.sum ./
RUN go mod download

# Build
COPY . $GOPATH/src/everoute
RUN mkdir -p /opt/everoute/bin && \
    make bin && \
    cp $GOPATH/src/everoute/bin/* /opt/everoute/bin/

FROM alpine

COPY --from=builder /opt/everoute/bin/* /opt/everoute/bin/

WORKDIR /opt/everoute/bin
ENV PATH=${PATH}:/opt/everoute/bin
