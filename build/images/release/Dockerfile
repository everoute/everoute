FROM golang:1.22.0 as builder

# Download deps
RUN mkdir -p $GOPATH/src/everoute
WORKDIR $GOPATH/src/everoute

RUN mkdir -p /opt/everoute/bin

# download CNI plugins
ARG CNI_BINARIES_VERSION=v1.0.0
ARG TARGETARCH
RUN wget -q -O - https://github.com/containernetworking/plugins/releases/download/$CNI_BINARIES_VERSION/cni-plugins-linux-$TARGETARCH-$CNI_BINARIES_VERSION.tgz | tar xz -C /opt/everoute/bin ./host-local ./loopback ./portmap

ADD go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

ADD ./build/script/* /opt/everoute/bin/
ADD . $GOPATH/src/everoute

# Build
RUN --mount=type=cache,target=/root/.cache/go-build --mount=type=cache,target=/go/pkg/mod make bin

RUN cp $GOPATH/src/everoute/bin/* /opt/everoute/bin/
RUN chmod 755 /opt/everoute/bin/*

#FROM ubuntu
FROM ubuntu:22.04
ARG TARGETOS
ARG TARGETARCH
RUN echo "platform $TARGETOS $TARGETARCH"

RUN apt update && apt install -y openvswitch-switch=2.17.* iptables \
    iproute2 tcpdump wget ipset && rm -rf /var/lib/apt/lists/*

#RUN install yq
RUN wget -qO /usr/local/bin/yq https://github.com/mikefarah/yq/releases/latest/download/yq_${TARGETOS}_${TARGETARCH} && chmod a+x /usr/local/bin/yq

# Automatically detect iptables mode (legacy or nf_tables) from baseOS
RUN ln -s -f /opt/everoute/bin/iptables-wrapper /etc/alternatives/iptables

RUN mkdir -p /opt/everoute/bin
COPY --from=builder /opt/everoute/bin/* /opt/everoute/bin/

WORKDIR /opt/everoute/bin
ENV PATH=${PATH}:/opt/everoute/bin
