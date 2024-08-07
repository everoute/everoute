FROM golang:1.19

ENV GOPROXY=http://goproxy.smartx.com,https://proxy.golang.org,direct
ENV K8S_VERSION=1.27.7
RUN go install github.com/99designs/gqlgen@v0.17.16 && \
    go install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.6.2 && \
    go install github.com/golang/mock/mockgen@v1.6.0 && \
    go install github.com/golang/protobuf/protoc-gen-go@v1.5.2 && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1 && \
    go install github.com/daixiang0/gci@v0.3.3 && \
    go install github.com/ahmetb/gen-crd-api-reference-docs@v0.3.0 && \
    go install k8s.io/code-generator/cmd/client-gen@kubernetes-$K8S_VERSION && \
    go install k8s.io/code-generator/cmd/lister-gen@kubernetes-$K8S_VERSION && \
    go install k8s.io/code-generator/cmd/informer-gen@kubernetes-$K8S_VERSION && \
    go clean -cache

ENV APISERVER_BOOT_RELEASE_URL=https://github.com/kubernetes-sigs/apiserver-builder-alpha/releases/download/v1.18.0/apiserver-builder-alpha-v1.18.0-linux-amd64.tar.gz
RUN wget -qO- $APISERVER_BOOT_RELEASE_URL | tar -C /go -zxf -

ENV PROTOC_RELEASE_URL=https://github.com/protocolbuffers/protobuf/releases/download/v3.17.3/protoc-3.17.3-linux-x86_64.zip
RUN apt update && apt install -y zip && rm -rf /var/lib/apt/lists/*
RUN wget -O protoc.zip $PROTOC_RELEASE_URL && unzip -d /usr/local protoc.zip && rm -rf protoc.zip
RUN curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

ENV GOROOT=/usr/local/go
