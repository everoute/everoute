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

	SkipWebhookLabelKey = "everoute-skip-webhook"

	PktMarkSetValue   uint64 = 0x1
	PktMarkResetValue uint64 = 0x0

	// ct zone used by securitypolicy
	CTZoneForPolicy uint16 = 65520

	// endpoint
	EndpointExternalIDKey = "iface-id"
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
)
