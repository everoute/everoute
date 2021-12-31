FROM golang:1.15 as builder

# Download deps
RUN mkdir -p $GOPATH/src/everoute
WORKDIR $GOPATH/src/everoute

RUN mkdir -p /opt/everoute/bin

# download CNI plugins
ARG CNI_BINARIES_VERSION=v1.0.0
ARG TARGETARCH
RUN wget -q -O - https://github.com/containernetworking/plugins/releases/download/$CNI_BINARIES_VERSION/cni-plugins-linux-$TARGETARCH-$CNI_BINARIES_VERSION.tgz | tar xz -C /opt/everoute/bin ./host-local ./loopback ./portmap

ADD go.mod go.sum ./
RUN go mod download

ADD ./build/script/* /opt/everoute/bin/
ADD . $GOPATH/src/everoute

# Build
RUN make bin

RUN cp $GOPATH/src/everoute/bin/* /opt/everoute/bin/
RUN chmod 755 /opt/everoute/bin/*

#FROM ubuntu
FROM ubuntu:20.04

#RUN apk update && apk add openvswitch
RUN apt update && apt install -y openvswitch-switch=2.13.3-0ubuntu0.20.04.2 iproute2 iptables tcpdump && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/everoute/bin
COPY --from=builder /opt/everoute/bin/* /opt/everoute/bin/

WORKDIR /opt/everoute/bin
ENV PATH=${PATH}:/opt/everoute/bin
