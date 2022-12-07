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

const (
	// InternalWhitelistPriority is the priority of internal whitelist IP, we set different priorities
	// with NormalPolicyRulePriority to make sure normal rules won't cover internal whitelist rules
	InternalWhitelistPriority       = 120
	NormalPolicyRulePriority        = 100
	DefaultPolicyRulePriority       = 70
	GlobalDefaultPolicyRulePriority = 40

	DefaultMaxConcurrentReconciles   = 4
	NumOfRetainedGroupMembersPatches = 3
	DependentsCleanFinalizer         = "finalizer.everoute.io/dependentsclean"
	OwnerGroupLabelKey               = "label.everoute.io/ownergroup"
	OwnerPolicyLabelKey              = "label.everoute.io/ownerpolicy"
	IsGlobalPolicyRuleLabel          = "label.everoute.io/isglobalpolicy"

	// Tier0 used for isolation policy and forensic one side drop
	Tier0 = "tier0"
	// Tier1 used for forensic policy
	Tier1 = "tier1"
	// Tier2 used for security policy and global policy
	Tier2 = "tier2"

	SecurityPolicyByEndpointGroupIndex = "SecurityPolicyByEndpointGroupIndex"

	EverouteWebhookName     = "validator.everoute.io"
	EverouteSecretName      = "everoute-controller-tls"
	EverouteSecretNamespace = "kube-system"

	ControllerRuntimeQPS   = 1000.0
	ControllerRuntimeBurst = 2000

	AgentNodeNameENV    = "NODE_NAME"
	AgentNameConfigPath = "/var/lib/everoute/agent/name"

	EverouteComponentType = 0x0

	RPCSocketAddr   = "/var/lib/everoute/rpc.sock"
	EverouteLibPath = "/var/lib/everoute"

	AllEpWithNamedPort = "all-endpoints-with-named-port"
)

const (
	OVSReg0 = 0
	OVSReg3 = 3
	OVSReg4 = 4
	OVSReg6 = 6
)
