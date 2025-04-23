# This dockerfile is used to build the unit-test image.
# It is used to run the unit-test container.

FROM golang:1.23 as downloader

ENV ETCD_RELEASE_URL=https://github.com/etcd-io/etcd/releases/download
ENV ETCD_VERSION=v3.5.6
RUN curl -L ${ETCD_RELEASE_URL}/${ETCD_VERSION}/etcd-${ETCD_VERSION}-linux-amd64.tar.gz -o /tmp/etcd-${ETCD_VERSION}-linux-amd64.tar && \
    tar -xf /tmp/etcd-${ETCD_VERSION}-linux-amd64.tar -C /usr/local/bin --strip-components=1 --extract etcd-${ETCD_VERSION}-linux-amd64/etcd

ENV KUBERNETES_RELEASE_URL=https://storage.googleapis.com/kubernetes-release/release
ENV KUBERNETES_VERSION=v1.24.17
RUN curl -L ${KUBERNETES_RELEASE_URL}/${KUBERNETES_VERSION}/bin/linux/amd64/kube-apiserver -o /usr/local/bin/kube-apiserver && \
    chmod +x /usr/local/bin/kube-apiserver

FROM ubuntu:22.04

# install openvswitch and dependencies
RUN apt update && \
    apt install -y --no-install-recommends iptables make sudo ca-certificates gcc libc6-dev \
      openvswitch-switch=2.17.* ssh curl iproute2 iputils-ping && \
    apt clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

COPY --from=downloader /usr/local/bin/kube-apiserver /usr/local/bin/etcd /usr/local/kubebuilder/bin/
COPY --from=downloader /usr/local/go /usr/local/go
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENV PATH=${PATH}:/usr/local/go/bin
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
