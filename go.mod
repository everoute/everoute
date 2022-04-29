module github.com/everoute/everoute

go 1.15

require (
	github.com/99designs/gqlgen v0.13.0
	github.com/Shopify/sarama v1.19.0
	github.com/Shopify/toxiproxy v2.1.4+incompatible // indirect
	github.com/Sirupsen/logrus v0.8.8-0.20160119000032-f7f79f729e0f
	github.com/alessio/shellescape v1.4.1
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/containernetworking/cni v1.0.0
	github.com/containernetworking/plugins v1.0.0
	github.com/contiv/libOpenflow v0.0.0-20200107061746-e3817550c83b
	github.com/contiv/libovsdb v0.0.0-20160406174930-bbc744d8ddc8
	github.com/contiv/ofnet v0.0.0-20180104211757-c080e5b6e9be
	github.com/coreos/go-iptables v0.6.0
	github.com/eapache/go-resiliency v1.2.0 // indirect
	github.com/eapache/go-xerial-snappy v0.0.0-20180814174437-776d5712da21 // indirect
	github.com/fatih/color v1.7.0
	github.com/fsnotify/fsnotify v1.5.1
	github.com/gertd/go-pluralize v0.1.7
	github.com/go-logr/logr v0.2.1 // indirect
	github.com/go-openapi/spec v0.19.3
	github.com/go-ping/ping v0.0.0-20210506233800-ff8be3320020
	github.com/google/gopacket v1.1.18
	github.com/gorilla/websocket v1.4.2
	github.com/hashicorp/go-retryablehttp v0.7.0
	github.com/j-keck/arping v1.0.2
	github.com/mdlayher/netlink v1.4.1
	github.com/onsi/ginkgo v1.16.4
	github.com/onsi/gomega v1.15.0
	github.com/pkg/errors v0.9.1
	github.com/rcrowley/go-metrics v0.0.0-20181016184325-3113b8401b8a // indirect
	github.com/spf13/cobra v1.1.3
	github.com/streamrail/concurrent-map v0.0.0-20160823150647-8bf1e9bacbf6
	github.com/ti-mo/conntrack v0.4.0
	github.com/ti-mo/netfilter v0.3.1
	github.com/vektah/gqlparser/v2 v2.1.0
	github.com/vishvananda/netlink v1.1.1-0.20210330154013-f5de75959ad5
	golang.org/x/crypto v0.0.0-20220128200615-198e4374d7ed
	golang.org/x/sys v0.0.0-20211216021012-1d35b9e2eb4e
	google.golang.org/grpc v1.38.0
	google.golang.org/protobuf v1.26.0
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.22.2
	k8s.io/apimachinery v0.22.2
	k8s.io/cli-runtime v0.20.1
	k8s.io/client-go v0.22.2
	k8s.io/klog v1.0.0
	k8s.io/kube-openapi v0.0.0-20210421082810-95288971da7e
	k8s.io/kubernetes v1.13.0
	k8s.io/utils v0.0.0-20210819203725-bdf08cb9a70a
	sigs.k8s.io/controller-runtime v0.10.2
)

replace (
	github.com/contiv/libOpenflow => github.com/everoute/libOpenflow v0.0.0-20210716071814-4ef09249fae5
	github.com/contiv/libovsdb => github.com/everoute/libovsdb v0.0.0-20210326110222-6c508538aa65
	github.com/contiv/ofnet => github.com/cl1111/ofnet v0.0.0-20220429094007-fff3c721ed59
	github.com/osrg/gobgp => github.com/everoute/gobgp v0.0.0-20210127101833-12edfc1f4514
	k8s.io/api v0.22.2 => k8s.io/api v0.20.6
	k8s.io/apimachinery v0.22.2 => k8s.io/apimachinery v0.20.6
	k8s.io/client-go v0.22.2 => k8s.io/client-go v0.20.6
	k8s.io/kube-openapi v0.0.0-20210421082810-95288971da7e => k8s.io/kube-openapi v0.0.0-20201113171705-d219536bb9fd
	k8s.io/utils v0.0.0-20210819203725-bdf08cb9a70a => k8s.io/utils v0.0.0-20210819203725-bdf08cb9a70a
	sigs.k8s.io/controller-runtime v0.10.2 => sigs.k8s.io/controller-runtime v0.6.0
)
