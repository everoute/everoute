package ms

import (
	"time"

	"k8s.io/apimachinery/pkg/types"
)

const (
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

	MetricPolicyRuleFlowIDUsedCount = "rule_flowid_used_count"
	MetricPolicyRuleFlowIDExhaust   = "rule_flowid_exhaust"

	// globalRule
	GlobalRuleFirstDelayTime = 20 * time.Second
	GlobalRuleDelayTimeout   = 5 * time.Minute

	// #nosec G101
	DefaultTowerTokenFile = "/tmp/towertoken"

	ComputeClustersConfigMapName = "associate-compute-clusters"

	// used in shareIP
	ALLInterfaceIDs = "ALL"
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

var (
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
