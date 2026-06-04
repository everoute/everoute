package datapath

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPolicyBridgeMatchDefaultRuleFlowID(t *testing.T) {
	allo := NewPolicyFlowIDAlloctor()
	seqID, err := allo.Allocate()
	assert.NoError(t, err)

	policyBridge := &PolicyBridge{
		BaseBridge: BaseBridge{
			datapathManager: &DpManager{FlowIDAlloctorForRule: allo},
			roundInfo:       &RoundInfo{currentRoundNum: 4},
		},
		defaultRuleSeqID: seqID,
	}

	match, err := policyBridge.MatchDefaultRuleFlowID(allo.AssemblyFlowID(4, seqID))
	assert.NoError(t, err)
	assert.True(t, match)

	match, err = policyBridge.MatchDefaultRuleFlowID(allo.AssemblyFlowID(3, seqID))
	assert.NoError(t, err)
	assert.False(t, match)
}
