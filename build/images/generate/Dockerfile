FROM registry.smtx.io/sdn-base/golang:1.26

ENV APISERVER_BOOT_RELEASE_URL=https://github.com/kubernetes-sigs/apiserver-builder-alpha/releases/download/v1.18.0/apiserver-builder-alpha-v1.18.0-linux-amd64.tar.gz
RUN wget -qO- $APISERVER_BOOT_RELEASE_URL | tar -C /go -zxf -
RUN rm /go/bin/deepcopy-gen

ENV GOPROXY=https://goproxy.cn,https://proxy.golang.org,direct
ENV K8S_VERSION=1.27.7

# Keep gqlgen v0.17.16 for stable generated code, but upgrade its x/tools
# dependency to avoid go/types panics on Go 1.26. A temporary module lets
# go install (without @version) use the upgraded dependency graph;
# tools.go keeps gqlgen in that graph when go mod tidy runs.
RUN mkdir -p /tmp/gqlgen-build && cd /tmp/gqlgen-build && \
    go mod init gqlgen-build && \
    printf '//go:build tools\n\npackage tools\n\nimport _ "github.com/99designs/gqlgen"\n' > tools.go && \
    go get github.com/99designs/gqlgen@v0.17.16 && \
    go get golang.org/x/tools@v0.52.0 && \
    go mod tidy && \
    GOBIN=/go/bin go install github.com/99designs/gqlgen && \
    rm -rf /tmp/gqlgen-build

RUN go install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.18.0 && \
    go install github.com/golang/mock/mockgen@v1.6.0 && \
    go install github.com/golang/protobuf/protoc-gen-go@v1.5.2 && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1 && \
    go install github.com/daixiang0/gci@v0.13.5 && \
    go install github.com/ahmetb/gen-crd-api-reference-docs@v0.3.0 && \
    go install k8s.io/code-generator/cmd/deepcopy-gen@kubernetes-$K8S_VERSION && \
    go install k8s.io/code-generator/cmd/client-gen@kubernetes-$K8S_VERSION && \
    go install k8s.io/code-generator/cmd/lister-gen@kubernetes-$K8S_VERSION && \
    go install k8s.io/code-generator/cmd/informer-gen@kubernetes-$K8S_VERSION && \
    go clean -cache

ENV PROTOC_RELEASE_URL=https://github.com/protocolbuffers/protobuf/releases/download/v3.17.3/protoc-3.17.3-linux-x86_64.zip
RUN apt update && apt install -y zip && rm -rf /var/lib/apt/lists/*
RUN wget -O protoc.zip $PROTOC_RELEASE_URL && unzip -d /usr/local protoc.zip && rm -rf protoc.zip
RUN curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

ENV GOROOT=/usr/local/go
