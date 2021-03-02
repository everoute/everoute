module github.com/smartxworks/lynx

go 1.15

require (
	github.com/agiledragon/gomonkey v2.0.2+incompatible
	github.com/armon/go-radix v1.0.0 // indirect
	github.com/cenkalti/hub v1.0.1 // indirect
	github.com/cenkalti/rpc2 v0.0.0-20210220005819-4a29bc83afe1 // indirect
	github.com/contiv/libOpenflow v0.0.0-20201116154255-01db743640b1 // indirect
	github.com/contiv/libovsdb v0.0.0-20160406174930-bbc744d8ddc8
	github.com/contiv/ofnet v0.0.0-20180104211757-c080e5b6e9be
	github.com/eapache/channels v1.1.0 // indirect
	github.com/eapache/queue v1.1.0 // indirect
	github.com/go-logr/logr v0.1.0
	github.com/go-openapi/spec v0.19.3
	github.com/influxdata/influxdb v1.8.4 // indirect
	github.com/onsi/ginkgo v1.11.0
	github.com/onsi/gomega v1.8.1
	github.com/satori/go.uuid v1.2.0 // indirect
	github.com/streamrail/concurrent-map v0.0.0-20160823150647-8bf1e9bacbf6 // indirect
	github.com/vishvananda/netlink v1.1.0 // indirect
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637 // indirect
	k8s.io/api v0.18.4
	k8s.io/apimachinery v0.18.4
	k8s.io/client-go v0.18.4
	k8s.io/klog v1.0.0
	k8s.io/kube-openapi v0.0.0-20200410145947-61e04a5be9a6
	sigs.k8s.io/controller-runtime v0.6.0
)

replace (
	github.com/contiv/libOpenflow => github.com/echkenluo/libOpenflow v0.0.0-20210303025312-9765e623c87e
	github.com/contiv/ofnet => github.com/echkenluo/ofnet v0.0.0-20210303101219-cb64f6aab9c9
	github.com/osrg/gobgp => github.com/zwtop/gobgp v0.0.0-20210127101833-12edfc1f4514
)
