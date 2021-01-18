CONTROLLER_GEN=$(shell which controller-gen)
APISERVER_BOOT=$(shell which apiserver-boot)

all: codegen manifests controller

controller: fmt vet
	go build -o bin/lynx-controller cmd/lynx-controller/main.go

# Generate deepcopy, client, openapi codes
codegen:
	$(APISERVER_BOOT) build generated --generator openapi --generator client --generator deepcopy --copyright hack/boilerplate.go.txt

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
