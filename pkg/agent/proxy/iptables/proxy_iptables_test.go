package iptables

import (
	"strings"
	"testing"

	"github.com/everoute/everoute/pkg/constants"
)

func TestGetRuleSpecByIPSet(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		exp  string
	}{
		{
			name: "nodeport svc tcp",
			arg:  constants.IPSetNameNPSvcTCP,
			exp:  "-p tcp -m set --match-set er-npsvc-tcp dst -j MARK --set-xmark 0x10000000/0x10000000",
		},
		{
			name: "nodeport svc udp",
			arg:  constants.IPSetNameNPSvcUDP,
			exp:  "-p udp -m set --match-set er-npsvc-udp dst -j MARK --set-xmark 0x10000000/0x10000000",
		},
		{
			name: "lb svc",
			arg:  constants.IPSetNameLBSvc,
			exp:  "-m set --match-set er-lbsvc dst,dst -j MARK --set-xmark 0x10000000/0x10000000",
		},
	}

	for _, c := range tests{
		res := getRuleSpecByIPSet(c.arg)
		if strings.Join(res, " ") != c.exp {
			t.Errorf("test %s failed, res is %s, exp is %s", c.name, strings.Join(res, " ") , c.exp)
		}
	}
}
