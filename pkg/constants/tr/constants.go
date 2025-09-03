package tr

import "time"

const (
	NicInExternalIDKeyPrefix  string = "tr-in-"
	NicOutExternalIDKeyPrefix string = "tr-out-"

	FlowIDPrefix           uint64 = 1 << 61
	FlowIDForTRNicMask     uint64 = 0xe000_0000_0fff_ffc0 // bit 61-63, bit 6-27
	FlowIDForTRNicMatch    uint64 = 0x2000_0000_0000_0000
	FlowIDForTRNicSuffix   uint32 = 0
	FlowIDForHealthySuffix uint32 = 0x1 << 6
	FlowIDForHealthyMask   uint64 = 0xe000_0000_0fff_ffc0
	FlowIDForHealthyMatch  uint64 = 0x2000_0000_0000_0040
	FlowIDRuleBegin        uint32 = 0x0800_0000
	FlowIDRuleEnd          uint32 = 0x083f_ffff

	DpActionMaxRetryTimes = 5

	DPIHealthyCheckTimeout = 3 * time.Second
	DPIHealthyCheckPeriod  = 3 * time.Second
)

var (
	SvcChainBridgeName = "ovsbr-niahccvs"
)
