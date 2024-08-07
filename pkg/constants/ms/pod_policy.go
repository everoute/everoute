package ms

const (
	// sks vm label
	SksManagedLabelKey   = "sks-managed"
	SksManagedLabelValue = "true"

	// eic pod namespace
	SKSObjectNamespace = "sks-sync-object"

	// eic networkpolicy prefix
	SKSNetworkpolicyPrefix = "np.sks-"

	// eic pod label
	SKSLabelKeyCluster         = "sks-cluster"
	SKSLabelKeyObjectName      = "sks-object-name"
	SKSLabelKeyObjectNamespace = "sks-object-namespace"

	// k8s management platform kubeconfig
	K8sMPKubeconfigNameInCloudPlatform = "sks-mgmt-kubeconfig"
	K8sMPKubeconfigNsInCloudPlatform   = "default"
	K8sMPKubeconfigName                = "k8s-mgmt-kubeconfig"
)
