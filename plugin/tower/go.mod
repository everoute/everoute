module github.com/smartxworks/lynx/plugin/tower

go 1.15

require (
	github.com/99designs/gqlgen v0.13.0
	github.com/gertd/go-pluralize v0.1.7
	github.com/gorilla/websocket v1.4.2
	github.com/onsi/ginkgo v1.13.0
	github.com/onsi/gomega v1.10.1
	github.com/smartxworks/lynx v0.0.0
	github.com/vektah/gqlparser/v2 v2.1.0
	google.golang.org/grpc v1.35.0
	gopkg.in/yaml.v2 v2.3.0
	k8s.io/apimachinery v0.20.1
	k8s.io/client-go v0.20.1
	k8s.io/klog v1.0.0
	k8s.io/klog/v2 v2.4.0
	k8s.io/utils v0.0.0-20201110183641-67b214c5f920
)

replace (
	github.com/contiv/libOpenflow => github.com/echkenluo/libOpenflow v0.0.0-20210415080703-4361a8a1982d
	github.com/contiv/libovsdb => github.com/smartxworks/libovsdb v0.0.0-20210326110222-6c508538aa65
	github.com/contiv/ofnet => github.com/smartxworks/ofnet v0.0.0-20210421082223-e16c95931aae
	github.com/osrg/gobgp => github.com/zwtop/gobgp v0.0.0-20210127101833-12edfc1f4514
	github.com/smartxworks/lynx => ../..
)
