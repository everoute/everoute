module github.com/smartxworks/lynx

go 1.15

require (
	github.com/agiledragon/gomonkey v2.0.2+incompatible
	github.com/cenkalti/rpc2 v0.0.0-20210220005819-4a29bc83afe1 // indirect
	github.com/contiv/libovsdb v0.0.0-20160406174930-bbc744d8ddc8
	github.com/contiv/ofnet v0.0.0-00010101000000-000000000000
	github.com/go-logr/logr v0.4.0 // indirect
	github.com/go-logr/zapr v0.3.1-0.20210105192823-aced49e5db50 // indirect
	github.com/go-openapi/spec v0.19.3
	github.com/kr/text v0.2.0 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.2-0.20181231171920-c182affec369 // indirect
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/onsi/ginkgo v1.13.0
	github.com/onsi/gomega v1.10.1
	github.com/prometheus/client_golang v1.7.1 // indirect
	github.com/prometheus/procfs v0.2.0 // indirect
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
	k8s.io/api v0.20.1
	k8s.io/apimachinery v0.20.1
	k8s.io/client-go v0.20.1
	k8s.io/klog v1.0.0
	k8s.io/kube-openapi v0.0.0-20201113171705-d219536bb9fd
	sigs.k8s.io/controller-runtime v0.6.0
)

replace (
	github.com/contiv/libOpenflow => github.com/echkenluo/libOpenflow v0.0.0-20210303025312-9765e623c87e
	github.com/contiv/ofnet => github.com/smartxworks/ofnet v0.0.0-20210315095710-7f729f6145f2
	github.com/osrg/gobgp => github.com/zwtop/gobgp v0.0.0-20210127101833-12edfc1f4514
)
