module github.com/smartxworks/lynx

go 1.15

require (
	github.com/99designs/gqlgen v0.13.0
	github.com/agiledragon/gomonkey v2.0.2+incompatible
	github.com/cenk/hub v1.0.1 // indirect
	github.com/contiv/libovsdb v0.0.0
	github.com/contiv/ofnet v0.0.0-00010101000000-000000000000
	github.com/fatih/color v1.7.0
	github.com/gertd/go-pluralize v0.1.7
	github.com/go-logr/logr v0.4.0 // indirect
	github.com/go-openapi/spec v0.19.3
	github.com/go-ping/ping v0.0.0-20210506233800-ff8be3320020
	github.com/gorilla/websocket v1.4.2
	github.com/hashicorp/go-retryablehttp v0.7.0
	github.com/j-keck/arping v1.0.2
	github.com/onsi/ginkgo v1.13.0
	github.com/onsi/gomega v1.10.1
	github.com/spf13/cobra v1.1.1
	github.com/vektah/gqlparser/v2 v2.1.0
	golang.org/x/crypto v0.0.0-20201002170205-7f63de1d35b0
	golang.org/x/sys v0.0.0-20201112073958-5cba982894dd
	google.golang.org/grpc v1.35.0
	gopkg.in/yaml.v2 v2.3.0
	k8s.io/api v0.20.1
	k8s.io/apimachinery v0.20.1
	k8s.io/cli-runtime v0.20.1
	k8s.io/client-go v0.20.1
	k8s.io/klog v1.0.0
	k8s.io/kube-openapi v0.0.0-20201113171705-d219536bb9fd
	k8s.io/utils v0.0.0-20201110183641-67b214c5f920
	sigs.k8s.io/controller-runtime v0.6.0
)

replace (
	github.com/contiv/libOpenflow => github.com/echkenluo/libOpenflow v0.0.0-20210415080703-4361a8a1982d
	github.com/contiv/libovsdb => github.com/smartxworks/libovsdb v0.0.0-20210326110222-6c508538aa65
	github.com/contiv/ofnet => github.com/smartxworks/ofnet v0.0.0-20210728112237-9d1e0ceb2424
	github.com/osrg/gobgp => github.com/zwtop/gobgp v0.0.0-20210127101833-12edfc1f4514
)
