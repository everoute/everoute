package ms

const (
	// eic pod namespace
	SKSObjectNamespace = "sks-sync-object"

	// eic networkpolicy prefix
	SKSNetworkpolicyPrefix = "np.sks-"

	// sks label
	SKSLabelKeyCluster          = "sks-cluster"
	SKSLabelKeyClusterName      = "everoute.io/ksc-name"
	SKSLabelKeyClusterNamespace = "everoute.io/ksc-namespace"
	SKSLabelKeyObjectName       = "sks-object-name"
	SKSLabelKeyObjectNamespace  = "sks-object-namespace"

	EICLabelKeyObjectNamespace = "everoute.io/eic-object-namespace"
	EICLabelKeyClusterID       = "everoute.io/k8scluster"

	// k8s management platform kubeconfig
	K8sMPKubeconfigNsInCloudPlatform = "default"
	K8sMPKubeconfigName              = "k8s-mgmt-kubeconfig"

	ProductEveroute = "everoute"
	ProductANS      = "ans"
)

var K8sMPKubeconfigNameInCloudPlatform string
