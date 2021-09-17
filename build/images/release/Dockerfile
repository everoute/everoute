FROM golang:1.17 as builder

# Download deps
RUN mkdir -p $GOPATH/src/lynx
WORKDIR $GOPATH/src/lynx

COPY go.mod go.sum ./
RUN go mod download

# Build
COPY . $GOPATH/src/lynx
RUN mkdir -p /opt/lynx/bin && \
    make bin && \
    cp $GOPATH/src/lynx/bin/* /opt/lynx/bin/

FROM alpine

COPY --from=builder /opt/lynx/bin/* /opt/lynx/bin/

WORKDIR /opt/lynx/bin
ENV PATH=${PATH}:/opt/lynx/bin
