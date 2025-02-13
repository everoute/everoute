FROM golang:1.20 as builder

WORKDIR $GOPATH/src/github.com/everoute/everoute/
ADD go.* $GOPATH/src/github.com/everoute/everoute/
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . $GOPATH/src/github.com/everoute/everoute/

ENV CGO_ENABLED=0
ARG GO_LDFLAGS=""

RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod \
      go build -o bin/erctl -ldflags "${GO_LDFLAGS}" \
      $GOPATH/src/github.com/everoute/everoute/cmd/everoute-cli/.

RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod \
      go build -o bin/erdeploy -ldflags "${GO_LDFLAGS}" \
      $GOPATH/src/github.com/everoute/everoute/cmd/everoute-deploy/.

RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod \
      go build -o bin/everoute-controller -ldflags "${GO_LDFLAGS}" \
      $GOPATH/src/github.com/everoute/everoute/cmd/everoute-controller/.

RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod \
      go build -o bin/everoute-agent -ldflags "${GO_LDFLAGS}" \
      $GOPATH/src/github.com/everoute/everoute/cmd/everoute-agent/.

FROM alpine:3.13.6

RUN apk update && apk add --no-cache openvswitch

ARG RELEASE_VERSION
ENV RELEASE_VERSION=${RELEASE_VERSION}
ARG GIT_COMMIT
ENV GIT_COMMIT=${GIT_COMMIT}

COPY --from=builder /go/src/github.com/everoute/everoute/bin/* /opt/everoute/bin/
