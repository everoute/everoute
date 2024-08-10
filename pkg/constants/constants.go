/*
Copyright 2021 The Everoute Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package constants

import (
	"time"

	"k8s.io/apimachinery/pkg/types"
)

const (
	// InternalWhitelistPriority is the priority of internal whitelist IP, we set different priorities
	// with NormalPolicyRulePriority to make sure normal rules won't cover internal whitelist rules
	InternalWhitelistPriority       = 510
	NormalPolicyRuleStartPriority   = 100
	DefaultPolicyRulePriority       = 70
	GlobalDefaultPolicyRulePriority = 40

	IfaceIPTimeoutDuration = 30 * time.Minute

	DefaultMaxConcurrentReconciles = 4
	DependentsCleanFinalizer       = "finalizer.everoute.io/dependentsclean"
	OwnerGroupLabelKey             = "label.everoute.io/ownergroup"
	OwnerPolicyLabelKey            = "label.everoute.io/ownerpolicy"
	IsGlobalPolicyRuleLabel        = "label.everoute.io/isglobalpolicy"

	// Tier0 used for isolation policy and forensic one side drop
	Tier0 = "tier0"
	// Tier1 used for forensic policy
	Tier1 = "tier1"
	// Tier2 used for security policy and global policy
	Tier2 = "tier2"
	// TierECP used for ecp network policy
	TierECP = "tier-ecp"

	SecurityPolicyByEndpointGroupIndex = "SecurityPolicyByEndpointGroupIndex"

	EverouteWebhookName     = "validator.everoute.io"
	EverouteIPAMWebhookName = "vipam.everoute.io"
	EverouteSecretName      = "everoute-controller-tls"

	ControllerRuntimeQPS   = 1000.0
	ControllerRuntimeBurst = 2000

	AgentNodeNameENV    = "NODE_NAME"
	AgentNameConfigPath = "/var/lib/everoute/agent/name"

	NamespaceNameENV = "NAMESPACE"

	EverouteComponentType = 0x0

	RPCSocketAddr   = "/var/lib/everoute/rpc.sock"
	EverouteLibPath = "/var/lib/everoute"

	AllEpWithNamedPort = "all-endpoints-with-named-port"

	HealthCheckPath = "/healthz"

	// sks related
	SksManagedLabelKey         = "sks-managed"
	SksManagedLabelValue       = "true"
	SKSObjectNamespace         = "sks-sync-object"
	SKSNetworkpolicyPrefix     = "np.sks-"
	SKSLabelKeyCluster         = "sks-cluster"
	SKSLabelKeyObjectName      = "sks-object-name"
	SKSLabelKeyObjectNamespace = "sks-object-namespace"

	SkipWebhookLabelKey = "everoute-skip-webhook"

	EncapModeGeneve = "geneve"
	GeneveHeaderLen = 50

	GwEpNamePrefix     = "gw-ep"
	GwEpExternalIDName = "gw-ep"

	EverouteIPAM = "everoute"

	GwIPPoolName = "everoute-built-in"

	LocalRulePriority        = 200
	FromGwLocalRulePriority  = 100
	SvcRulePriority          = 110
	ClusterIPSvcRulePriority = 111
	SvcLocalIPRulePriority   = 120

	FromGwLocalRouteTable = 100
	SvcToGWRouteTable     = 110

	// InternalSvcPktMarkBit pod request clusterIP svc, used in local bridge
	InternalSvcPktMarkBit = 29
	// ExternalSvcPktMarkBit nodeport/lb/clusterIP svc mark, used in uplink bridge and kernel route
	ExternalSvcPktMarkBit = 28
	// SvcLocalPktMarkBit set when ExternalTrafficPolicy=local
	SvcLocalPktMarkBit = 30

	PktMarkSetValue   uint64 = 0x1
	PktMarkResetValue uint64 = 0x0

	IPSetNameNPSvcTCP = "er-npsvc-tcp"
	IPSetNameNPSvcUDP = "er-npsvc-udp"
	IPSetNameLBSvc    = "er-lbsvc"

	IPtSvcChain   = "EVEROUTE-SVC"
	IPtNPSvcChain = "EVEROUTE-SVC-NP"

	// ct zone used by cni
	CTZoneNatBrFromLocal  = 65505
	CTZoneNatBrFromUplink = 65506
	CTZoneLocalBr         = 65510
	CTZoneUplinkBr        = 65503
	// ct zone used by securitypolicy
	CTZoneForPolicy uint16 = 65520

	// endpoint
	EndpointExternalIDKey = "iface-id"

	// metric
	MetricPath               = "/metrics"
	MetricNamespace          = "everoute"
	MetricSubSystem          = "ms"
	MetricIPMigrateCountName = "ip_migrate_count"
	MetricIPLabel            = "ip"
	MetricMaxIPNumInCache    = 2000

	MetricArpCount       = "arp_count"
	MetricArpCountReject = "arp_count_reject"

	MetricRuleEntryNumTotal        = "rule_entry_num_total"
	MetricRuleEntryNum             = "rule_entry_num"
	MetricRuleEntryNumLimit        = "rule_entry_num_limit"
	MetricRuleEntryPolicyNameLabel = "name"

	// GroupID
	GroupIDFileSuffix       = ".groupid"
	MaxGroupIter            = 15
	BitWidthGroupIter       = 4
	GroupIDUpdateUnit       = 100
	DeleteAllGroupThreshold = 1000000

	// globalRule
	GlobalRuleFirstDelayTime = 20 * time.Second
	GlobalRuleDelayTimeout   = 5 * time.Minute
)

const (
	/* logging tags key enum */

	LoggingTagPolicyID   = "PolicyID"
	LoggingTagPolicyName = "PolicyName"
	LoggingTagPolicyType = "PolicyType"

	/* logging policy type enum */

	LoggingTagPolicyTypeSecurityPolicyAllow = "SecurityPolicyAllow"
	LoggingTagPolicyTypeSecurityPolicyDeny  = "SecurityPolicyDeny"
	LoggingTagPolicyTypeQuarantinePolicy    = "QuarantinePolicy"
	LoggingTagPolicyTypeGlobalPolicy        = "GlobalPolicy"
)

const (
	OVSReg0 = 0
	OVSReg2 = 2
	OVSReg3 = 3
	OVSReg4 = 4
	OVSReg6 = 6
)

var (
	AlgNeedModules = []string{"nf_nat_ftp", "nf_conntrack_ftp", "nf_nat_tftp", "nf_conntrack_tftp"}

	// system policy
	ERvmPolicy = types.NamespacedName{
		Namespace: "tower-space",
		Name:      "tower.sp.internal-controller",
	}
	LBPolicy = types.NamespacedName{
		Namespace: "everoute-space",
		Name:      "internal-lb",
	}
	SysEPPolicy = types.NamespacedName{
		Namespace: "tower-space",
		Name:      "tower.sp.internal-system.endpoints",
	}
)
