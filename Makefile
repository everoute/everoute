CONTROLLER_GEN=$(shell which controller-gen)
APISERVER_BOOT=$(shell which apiserver-boot)

all: codegen manifests bin

bin: controller agent e2e-tools

images:
	docker build -f build/images/release/Dockerfile -t everoute/release .
	docker build -f build/images/generate/Dockerfile -t everoute/generate ./build/images/generate/

yaml:
	find deploy -name "*.yaml" | grep -v ^deploy/everoute.yaml$ | sort -u | xargs cat | cat > deploy/everoute.yaml

generate: codegen gqlgen protopb manifests yaml

docker-generate:
	$(eval WORKDIR := /go/src/github.com/everoute/everoute)
	docker run --rm -iu $$(id -u):$$(id -g) -w $(WORKDIR) -v $(CURDIR):$(WORKDIR) everoute/generate make generate

controller:
	CGO_ENABLED=0 go build -o bin/everoute-controller cmd/everoute-controller/main.go

agent:
	CGO_ENABLED=0 go build -o bin/everoute-agent cmd/everoute-agent/*.go

e2e-tools:
	CGO_ENABLED=0 go build -o bin/e2ectl tests/e2e/tools/e2ectl/*.go
	CGO_ENABLED=0 go build -o bin/net-utils tests/e2e/tools/net-utils/*.go

test:
	go test ./plugin/tower/pkg/controller/... ./pkg/... -v

cover-test:
	go test ./plugin/tower/pkg/controller/... ./pkg/... -coverprofile=coverage.out \
		-coverpkg=./pkg/...,./plugin/tower/pkg/controller/...

race-test:
	go test ./plugin/tower/pkg/controller/... ./pkg/... -race

e2e-test:
	go test ./tests/e2e/...

# Generate deepcopy, client, openapi codes
codegen: manifests
	$(APISERVER_BOOT) build generated --generator openapi --generator client --generator deepcopy --copyright hack/boilerplate.go.txt \
		--api-versions agent/v1alpha1 \
		--api-versions group/v1alpha1 \
		--api-versions policyrule/v1alpha1 \
		--api-versions security/v1alpha1

# Generate plugin-tower gql codes
gqlgen:
	cd plugin/tower/pkg/server/fake/ && gqlgen generate

protopb:
	protoc -I=. --go_out=plugins=grpc:.  pkg/apis/cni/v1alpha1/cni.proto

deploy-test:
	bash hack/deploy.sh

deploy-test-clean:
	bash hack/undeploy.sh

# Generate CRD manifests
manifests:
	$(CONTROLLER_GEN) crd paths="./pkg/apis/..." output:crd:dir=deploy/crds output:stdout

# Run go fmt against code
fmt:
	go fmt ./...

# Run go vet against code
vet:
	go vet ./...

clean:
	$(APISERVER_BOOT) build generated clean
