package datapath

import (
	"net"
	"testing"
)

func TestToEveroutePolicyRuleForCT(t *testing.T) {
	c := []struct {
		name string
		src  EveroutePolicyRule
		exp  EveroutePolicyRuleForCT
	}{
		{
			name: "complete rule",
			src: EveroutePolicyRule{
				RuleID:         "rule1",
				Priority:       400,
				Action:         EveroutePolicyAllow,
				SrcIPAddr:      "12.1.1.1",
				DstIPAddr:      "12.1.1.0/24",
				SrcPort:        60,
				SrcPortMask:    0xffff,
				DstPort:        12,
				IcmpTypeEnable: true,
				IcmpType:       13,
			},
			exp: EveroutePolicyRuleForCT{
				RuleID:         "rule1",
				SrcPort:        60,
				SrcIP:          &net.IP{12, 1, 1, 1},
				DstIPNet:       &net.IPNet{IP: net.IP{12, 1, 1, 0}, Mask: net.IPMask{255, 255, 255, 0}},
				SrcPortMask:    0xffff,
				DstPort:        12,
				IcmpTypeEnable: true,
				IcmpType:       13,
			},
		},
		{
			name: "no ip",
			src: EveroutePolicyRule{
				RuleID:         "rule1",
				Priority:       400,
				Action:         EveroutePolicyAllow,
				SrcIPAddr:      "",
				SrcPort:        60,
				SrcPortMask:    0xffff,
				DstPort:        12,
				IcmpTypeEnable: true,
				IcmpType:       13,
			},
			exp: EveroutePolicyRuleForCT{
				RuleID:         "rule1",
				SrcPort:        60,
				SrcPortMask:    0xffff,
				DstPort:        12,
				IcmpTypeEnable: true,
				IcmpType:       13,
			},
		},
		{
			name: "only src ip",
			src: EveroutePolicyRule{
				RuleID:         "rule1",
				Priority:       400,
				Action:         EveroutePolicyAllow,
				DstIPAddr:      "12.1.1.4",
				SrcPort:        60,
				SrcPortMask:    0xffff,
				DstPort:        12,
				IcmpTypeEnable: true,
				IcmpType:       13,
			},
			exp: EveroutePolicyRuleForCT{
				RuleID:         "rule1",
				DstIP:          &net.IP{12, 1, 1, 4},
				SrcPort:        60,
				SrcPortMask:    0xffff,
				DstPort:        12,
				IcmpTypeEnable: true,
				IcmpType:       13,
			},
		},
	}

	for _, cs := range c {
		res := cs.src.toEveroutePolicyRuleForCT()
		if cs.exp.SrcIP == nil {
			if res.SrcIP != nil {
				t.Errorf("test %s is failed, real is  %v, exp is %v", cs.name, res, cs.exp)
				continue
			}
		} else {
			if res.SrcIP == nil {
				t.Errorf("test %s is failed, real is  %v, exp is %v", cs.name, res, cs.exp)
				continue
			}
			if !cs.exp.SrcIP.Equal(*res.SrcIP) {
				t.Errorf("test %s is failed, real is  %v, exp is %v", cs.name, res, cs.exp)
				continue
			}
		}

		if cs.exp.DstIP == nil {
			if res.DstIP != nil {
				t.Errorf("test %s is failed, real is  %v, exp is %v", cs.name, res, cs.exp)
				continue
			}
		} else {
			if res.DstIP == nil {
				t.Errorf("test %s is failed, real is  %v, exp is %v", cs.name, res, cs.exp)
				continue
			}
			if !cs.exp.DstIP.Equal(*res.DstIP) {
				t.Errorf("test %s is failed, real is  %v, exp is %v", cs.name, res, cs.exp)
				continue
			}
		}

		if cs.exp.DstIPNet == nil {
			if res.DstIPNet != nil {
				t.Errorf("test %s is failed, real is  %v, exp is %v", cs.name, res, cs.exp)
				continue
			}
		} else {
			if res.DstIPNet == nil {
				t.Errorf("test %s is failed, real is  %v, exp is %v", cs.name, res, cs.exp)
				continue
			}
			if !cs.exp.DstIPNet.IP.Equal(res.DstIPNet.IP) {
				t.Errorf("test %s is failed, real is  %v, exp is %v", cs.name, res, cs.exp)
				continue
			}
		}

		if cs.exp.SrcIPNet == nil {
			if res.SrcIPNet != nil {
				t.Errorf("test %s is failed, real is  %v, exp is %v", cs.name, res, cs.exp)
				continue
			}
		} else {
			if res.SrcIPNet == nil {
				t.Errorf("test %s is failed, real is  %v, exp is %v", cs.name, res, cs.exp)
				continue
			}
			if !cs.exp.SrcIPNet.IP.Equal(res.SrcIPNet.IP) {
				t.Errorf("test %s is failed, real is  %v, exp is %v", cs.name, res, cs.exp)
				continue
			}
		}

		cs.exp.DstIP = nil
		cs.exp.DstIPNet = nil
		cs.exp.SrcIP = nil
		cs.exp.SrcIPNet = nil
		res.DstIP = nil
		res.DstIPNet = nil
		res.SrcIP = nil
		res.SrcIPNet = nil
		if cs.exp != res {
			t.Errorf("test %s is failed, real is  %v, exp is %v", cs.name, res, cs.exp)
			continue
		}
	}
}
