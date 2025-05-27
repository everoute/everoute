package tr

import "time"

const (
	NicInExternalIDKeyPrefix  string = "tr-in-"
	NicOutExternalIDKeyPrefix string = "tr-out-"

	FlowIDPrefix           uint64 = 1 << 61
	FlowIDForTRNicMask     uint64 = 0xe000_0000_0fff_ffc0 // bit 61-63, bit 6-27
	FlowIDForTRNicMatch    uint64 = 0x2000_0000_0000_0000
	FlowIDForTRNicSuffix   uint64 = 0
	FlowIDForHealthySuffix uint64 = 0x1 << 6
	FlowIDForHealthyMask   uint64 = 0xe000_0000_0fff_ffc0
	FlowIDForHealthyMatch  uint64 = 0x2000_0000_0000_0040
	FlowIDVariableLowBits  uint32 = 28
	FlowIDRuleFixBit       uint32 = 27

	DpActionMaxRetryTimes = 5

	DPIHealthyCheckTimeout = 3 * time.Second
	DPIHealthyCheckPeriod  = 3 * time.Second
)

var (
	SvcChainBridgeName = "ovsbr-niahccvs"
)
