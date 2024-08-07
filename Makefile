CONTROLLER_GEN=$(shell which controller-gen)
APISERVER_BOOT=$(shell which apiserver-boot)

bin: controller agent cni erctl

images: image image-generate

image-debug:
	docker buildx build -f build/images/release/Dockerfile -t registry.smtx.io/everoute/debug . --push

image:
	docker buildx build -f build/images/release/Dockerfile -t everoute/release . --load

image-generate:
	docker buildx build -f build/images/generate/Dockerfile -t everoute/generate ./build/images/generate/ --load

image-test:
	docker buildx build -f build/images/unit-test/Dockerfile -t everoute/unit-test ./build/images/unit-test/ --load

image-test-pull:
	docker pull registry.smtx.io/everoute/unit-test:latest

yaml:
	helm template -n kube-system deploy/chart > deploy/everoute.yaml

generate: codegen mock gqlgen protopb manifests yaml apidocs-gen
	find . -name "*.go" -exec gci write --Section Standard --Section Default --Section "Prefix(github.com/everoute/everoute)" {} +

docker-generate: image-generate
	$(eval WORKDIR := /go/src/github.com/everoute/everoute)
	docker run --rm -iu 0:0 -w $(WORKDIR) -v $(CURDIR):$(WORKDIR) everoute/generate make generate

docker-generate-ci:
	$(eval WORKDIR := /go/src/github.com/everoute/everoute)
	docker run --rm -iu 0:0 -w $(WORKDIR) -v $(CURDIR):$(WORKDIR) registry.smtx.io/everoute/generate make generate

controller:
	CGO_ENABLED=0 go build -o bin/everoute-controller cmd/everoute-controller/*.go

agent:
	CGO_ENABLED=0 go build -o bin/everoute-agent cmd/everoute-agent/*.go

cni:
	CGO_ENABLED=0 go build -o bin/everoute-cni cmd/everoute-cni/*.go

erctl:
	CGO_ENABLED=0 go build -o bin/erctl cmd/everoute-cli/*.go

e2e-tools:
	CGO_ENABLED=0 go build -o bin/e2ectl tests/e2e/tools/e2ectl/*.go
	CGO_ENABLED=0 go build -o bin/net-utils tests/e2e/tools/net-utils/*.go

agent-uuid:
	mkdir -p /var/lib/everoute/agent
	cat /proc/sys/kernel/random/uuid > /var/lib/everoute/agent/name

test: agent-uuid
	go test --gcflags=all=-l -p 1 ./plugin/... ./pkg/...

debug-test: image-test
	$(eval WORKDIR := /go/src/github.com/everoute/everoute)
	docker run --rm -iu 0:0 -w $(WORKDIR) -v $(CURDIR):$(WORKDIR) -v /lib/modules:/lib/modules --privileged everoute/unit-test bash

docker-test: image-test
	$(eval WORKDIR := /go/src/github.com/everoute/everoute)
	docker run --rm -iu 0:0 -w $(WORKDIR) -v $(CURDIR):$(WORKDIR) -v /lib/modules:/lib/modules --privileged everoute/unit-test make test

docker-test-ci: image-test-pull
	$(eval WORKDIR := /go/src/github.com/everoute/everoute)
	docker run --rm -iu 0:0 -w $(WORKDIR) -v $(CURDIR):$(WORKDIR) -v /lib/modules:/lib/modules --privileged registry.smtx.io/everoute/unit-test make test

cover-test: agent-uuid
	go test --gcflags=all=-l -p 1 ./plugin/... ./pkg/... -coverprofile=coverage.out \
		-coverpkg=./pkg/...,./plugin/tower/pkg/controller/...

docker-cover-test: image-test
	$(eval WORKDIR := /go/src/github.com/everoute/everoute)
	docker run --rm -iu 0:0 -w $(WORKDIR) -v $(CURDIR):$(WORKDIR) -v /lib/modules:/lib/modules --privileged everoute/unit-test make cover-test

docker-cover-test-ci: image-test-pull
	$(eval WORKDIR := /go/src/github.com/everoute/everoute)
	docker run --rm -iu 0:0 -w $(WORKDIR) -v $(CURDIR):$(WORKDIR) -v /lib/modules:/lib/modules --privileged registry.smtx.io/everoute/unit-test make cover-test

race-test: agent-uuid
	go test --gcflags=all=-l -p 1 ./plugin/... ./pkg/... -race

docker-race-test: image-test
	$(eval WORKDIR := /go/src/github.com/everoute/everoute)
	docker run --rm -iu 0:0 -w $(WORKDIR) -v $(CURDIR):$(WORKDIR) -v /lib/modules:/lib/modules --privileged everoute/unit-test make race-test

docker-race-test-ci: image-test-pull
	$(eval WORKDIR := /go/src/github.com/everoute/everoute)
	docker run --rm -iu 0:0 -w $(WORKDIR) -v $(CURDIR):$(WORKDIR) -v /lib/modules:/lib/modules --privileged registry.smtx.io/everoute/unit-test make race-test

e2e-test:
	go test ./tests/e2e/...

setup-e2e-env:
	sh -c "ssh-keygen -qN '' </dev/zero; cp ~/.ssh/id_rsa.pub ~/.ssh/authorized_keys"
	bash tests/e2e/scripts/e2e-setup.sh

docker-e2e-test-entry: setup-e2e-env
	go test ./tests/e2e/... -v

docker-e2e-test: image-test
	$(eval WORKDIR := /go/src/github.com/everoute/everoute)
	docker run --rm -iu 0:0 -e USER=root -w $(WORKDIR) -v $(CURDIR):$(WORKDIR) -v /lib/modules:/lib/modules --privileged everoute/unit-test make docker-e2e-test-entry

docker-e2e-test-ci:
	$(eval WORKDIR := /go/src/github.com/everoute/everoute)
	docker run --rm -iu 0:0 -e USER=root -w $(WORKDIR) -v $(CURDIR):$(WORKDIR) -v /lib/modules:/lib/modules --privileged registry.smtx.io/everoute/unit-test make docker-e2e-test-entry

docker-golint-check:
	$(eval WORKDIR := /go/src/github.com/everoute/everoute)
	docker run --rm -iu 0:0 -e USER=root -w $(WORKDIR) -v $(CURDIR):$(WORKDIR) golangci/golangci-lint:v1.53 golangci-lint run ./...

mock:
	rm -rf tests/mocks
	mockgen -destination=tests/mocks/mock_client.go -package mocks sigs.k8s.io/controller-runtime/pkg/client Client,StatusWriter

# Generate deepcopy, client, openapi codes
codegen: manifests
	$(APISERVER_BOOT) build generated --generator client --generator deepcopy --copyright hack/boilerplate.generatego.txt \
		--api-versions agent/v1alpha1 \
		--api-versions group/v1alpha1 \
		--api-versions security/v1alpha1 \
		--api-versions service/v1alpha1 \
		--api-versions pod/v1alpha1
	deepcopy-gen --go-header-file hack/boilerplate.generatego.txt -O zz_generated.deepcopy --input-dirs ./pkg/labels/...

# Generate plugin-tower gql codes
gqlgen:
	cd plugin/tower/pkg/server/fake/ && gqlgen generate

protopb:
	protoc -I=. --go_out=plugins=grpc:.  pkg/apis/rpc/v1alpha1/cni.proto
	protoc -I=. --go_out=plugins=grpc:.  pkg/apis/rpc/v1alpha1/collector.proto
	protoc -I=. --go_out=plugins=grpc:.  pkg/apis/rpc/v1alpha1/rule.proto

apidocs-gen:
	$(eval PATH := $$(PATH):$(shell go env GOPATH)/bin)
	which gen-crd-api-reference-docs || go install github.com/ahmetb/gen-crd-api-reference-docs@v0.3.0
	gen-crd-api-reference-docs --config docs/assets/apidocs-gen.json \
		--out-file docs/content/en/docs/reference/apidocs.html --template-dir docs/assets/templates/ \
		--api-dir ./pkg/apis/security/v1alpha1

# Generate CRD manifests
manifests:
	$(CONTROLLER_GEN) crd paths="./pkg/apis/..." output:crd:dir=deploy/chart/templates/crds output:stdout

# Run go fmt against code
fmt:
	go fmt ./...

# Run go vet against code
vet:
	go vet ./...

clean:
	$(APISERVER_BOOT) build generated clean
