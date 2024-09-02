package ms

const (
	// sks vm label
	SksManagedLabelKey   = "sks-managed"
	SksManagedLabelValue = "true"

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
	K8sMPKubeconfigNameInCloudPlatform = "sks-mgmt-kubeconfig"
	K8sMPKubeconfigNsInCloudPlatform   = "default"
	K8sMPKubeconfigName                = "k8s-mgmt-kubeconfig"
)
