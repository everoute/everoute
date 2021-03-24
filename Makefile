CONTROLLER_GEN=$(shell which controller-gen)
APISERVER_BOOT=$(shell which apiserver-boot)

all: codegen manifests bin

bin: controller

images:
	docker build -f build/images/release/Dockerfile -t lynx/release .

controller: fmt vet
	CGO_ENABLED=0 go build -o bin/lynx-controller cmd/lynx-controller/main.go

agent:
	go build -o bin/lynx-agent cmd/lynx-agent/*.go

test:
	go test ./pkg/...

cover-test:
	go test ./pkg/... -coverprofile=coverage.out -coverpkg=./pkg/...

race-test:
	go test ./pkg/... -race

# Generate deepcopy, client, openapi codes
codegen:
	$(APISERVER_BOOT) build generated --generator deepcopy --copyright hack/boilerplate.go.txt

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
