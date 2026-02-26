package datapath

import (
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/everoute/everoute/pkg/agent/datapath/conntrack"
)

func TestPolicySeqID(t *testing.T) {
	var id uint64 = 0xb8307028
	allo := NewPolicyFlowIDAlloctor()
	seqID, err := allo.GetSeqIDByFlowID(id)
	if err != nil {
		t.Errorf("expect return no err, real err is: %s", err)
	}
	res := allo.AssemblyFlowID(11, seqID)
	if res != id {
		t.Errorf("expect is %x, real is %x", id, res)
	}

	res = allo.AssemblyFlowID(12, seqID)
	if res != 0xc8307028 {
		t.Errorf("expect is %x, real is %x", 0xc8307028, res)
	}
}

// ipTo16 converts IP string to [16]byte (IPv4-mapped for IPv4)
func ipTo16(s string) [16]byte {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return addr.As16()
}

func TestToMatcher(t *testing.T) {
	cases := []struct {
		name    string
		src     EveroutePolicyRule
		wantErr bool
		check   func(t *testing.T, got conntrack.Matcher)
	}{
		{
			name: "complete rule with src and dst",
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
				IPFamily:       unix.AF_INET,
				IcmpType:       13,
			},
			wantErr: false,
			check: func(t *testing.T, got conntrack.Matcher) {
				if got.ID != "rule1" || got.SrcPort != 60 || got.DstPort != 12 {
					t.Errorf("ID/SrcPort/DstPort mismatch: got %+v", got)
				}
				expSrc := ipTo16("12.1.1.1")
				if got.SrcIP != expSrc {
					t.Errorf("SrcIP got %x, want %x", got.SrcIP, expSrc)
				}
				expDst := ipTo16("12.1.1.0")
				if got.DstIP != expDst {
					t.Errorf("DstIP got %x, want %x", got.DstIP, expDst)
				}
				// IPv4 in 128-bit space: single IP = 96+32=128, /24 = 96+24=120
				if got.SrcIPPrefixLen != 128 {
					t.Errorf("SrcIPPrefixLen want 128 (IPv4 single in 128-bit), got %d", got.SrcIPPrefixLen)
				}
				if got.DstIPPrefixLen != 120 {
					t.Errorf("DstIPPrefixLen want 120 (IPv4 /24 in 128-bit), got %d", got.DstIPPrefixLen)
				}
			},
		},
		{
			name: "no ip",
			src: EveroutePolicyRule{
				RuleID:         "rule1",
				Priority:       400,
				Action:         EveroutePolicyAllow,
				SrcIPAddr:      "",
				DstIPAddr:      "",
				SrcPort:        60,
				SrcPortMask:    0xffff,
				DstPort:        12,
				IPFamily:       unix.AF_INET,
				IcmpTypeEnable: true,
				IcmpType:       13,
			},
			wantErr: false,
			check: func(t *testing.T, got conntrack.Matcher) {
				if got.SrcIPPrefixLen != 0 || got.DstIPPrefixLen != 0 {
					t.Errorf("expect any IP (prefix 0), got Src=%d Dst=%d",
						got.SrcIPPrefixLen, got.DstIPPrefixLen)
				}
			},
		},
		{
			name: "only dst ip",
			src: EveroutePolicyRule{
				RuleID:         "rule1",
				Priority:       400,
				Action:         EveroutePolicyAllow,
				SrcIPAddr:      "",
				DstIPAddr:      "12.1.1.4",
				SrcPort:        60,
				SrcPortMask:    0xffff,
				DstPort:        12,
				IPFamily:       unix.AF_INET,
				IcmpTypeEnable: true,
				IcmpType:       13,
			},
			wantErr: false,
			check: func(t *testing.T, got conntrack.Matcher) {
				expDst := ipTo16("12.1.1.4")
				if got.DstIP != expDst {
					t.Errorf("DstIP got %x, want %x", got.DstIP, expDst)
				}
				// IPv4 single IP in 128-bit space = 96+32=128
				if got.DstIPPrefixLen != 128 {
					t.Errorf("DstIPPrefixLen want 128 (IPv4 single in 128-bit), got %d", got.DstIPPrefixLen)
				}
				if got.SrcIPPrefixLen != 0 {
					t.Errorf("SrcIPPrefixLen want 0 (any), got %d", got.SrcIPPrefixLen)
				}
			},
		},
		{
			name: "invalid src ip",
			src: EveroutePolicyRule{
				RuleID:    "rule1",
				SrcIPAddr: "invalid-ip",
			},
			wantErr: true,
		},
	}
	for _, cs := range cases {
		t.Run(cs.name, func(t *testing.T) {
			got, err := cs.src.ToMatcher()
			if (err != nil) != cs.wantErr {
				t.Fatalf("ToMatcher() err = %v, wantErr %v", err, cs.wantErr)
			}
			if cs.wantErr {
				return
			}
			if cs.check != nil {
				cs.check(t, got)
			}
		})
	}
}
