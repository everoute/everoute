package cmd

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestBuildConntrackMatchersFromSeparatedArgs(t *testing.T) {
	matcher, hasFilter, err := buildConntrackMatchers(
		[]string{
			"--protocol=tcp",
			"--orig-dst-port=80",
			"--",
			"--family=ipv6",
			"--protocol=udp",
			"--orig-dst-port=53",
		},
		"",
	)
	if err != nil {
		t.Fatalf("buildConntrackMatchers returned error: %v", err)
	}
	if !hasFilter {
		t.Fatalf("expected matcher to be built")
	}

	if !matcher.MatchConntrackFlow(makeConntrackFlow("10.0.0.1", "10.0.0.2", 12345, 80, unix.IPPROTO_TCP)) {
		t.Fatalf("expected tcp matcher to match")
	}
	if matcher.MatchConntrackFlow(makeConntrackFlow("10.0.0.1", "10.0.0.2", 12345, 53, unix.IPPROTO_UDP)) {
		t.Fatalf("did not expect ipv4 udp flow to match ipv6-scoped matcher")
	}
	if !matcher.MatchConntrackFlow(makeIPv6ConntrackFlow("2001:db8::1", "2001:db8::2", 12345, 53, unix.IPPROTO_UDP)) {
		t.Fatalf("expected ipv6 udp matcher to match")
	}
	if matcher.MatchConntrackFlow(makeConntrackFlow("10.0.0.1", "10.0.0.2", 12345, 443, unix.IPPROTO_TCP)) {
		t.Fatalf("did not expect unmatched flow to match")
	}
}

func TestBuildConntrackMatchersMatcherZoneWorks(t *testing.T) {
	matcher, hasFilter, err := buildConntrackMatchers(
		[]string{
			"--zone=7",
			"--protocol=tcp",
			"--orig-dst-port=80",
			"--",
			"--family=ipv6",
			"--zone=7",
			"--protocol=udp",
			"--orig-dst-port=53",
		},
		"",
	)
	if err != nil {
		t.Fatalf("buildConntrackMatchers returned error: %v", err)
	}
	if !hasFilter {
		t.Fatalf("expected matcher to be built")
	}

	flow1 := makeConntrackFlow("10.0.0.1", "10.0.0.2", 12345, 80, unix.IPPROTO_TCP)
	flow1.Zone = 7
	if !matcher.MatchConntrackFlow(flow1) {
		t.Fatalf("expected first zone-scoped matcher to match")
	}

	flow2 := makeIPv6ConntrackFlow("2001:db8::1", "2001:db8::2", 12345, 53, unix.IPPROTO_UDP)
	flow2.Zone = 7
	if !matcher.MatchConntrackFlow(flow2) {
		t.Fatalf("expected second zone-scoped matcher to match")
	}

	flow3 := makeIPv6ConntrackFlow("2001:db8::1", "2001:db8::2", 12345, 53, unix.IPPROTO_UDP)
	flow3.Zone = 8
	if matcher.MatchConntrackFlow(flow3) {
		t.Fatalf("did not expect flow in another zone to match")
	}
}

func TestBuildConntrackMatchersPortFilterWithoutProtocolDoesNotMatchICMP(t *testing.T) {
	matcher, hasFilter, err := buildConntrackMatchers(
		[]string{
			"--orig-src-ip=10.0.0.1",
			"--orig-dst-ip=10.0.0.2",
			"--orig-dst-port=80",
		},
		"",
	)
	if err != nil {
		t.Fatalf("buildConntrackMatchers returned error: %v", err)
	}
	if !hasFilter {
		t.Fatalf("expected matcher to be built")
	}

	if !matcher.MatchConntrackFlow(makeConntrackFlow("10.0.0.1", "10.0.0.2", 12345, 80, unix.IPPROTO_TCP)) {
		t.Fatalf("expected tcp flow to match port filter without protocol")
	}

	if matcher.MatchConntrackFlow(makeICMPConntrackFlow("10.0.0.1", "10.0.0.2", unix.IPPROTO_ICMP)) {
		t.Fatalf("did not expect icmp flow to match port filter without protocol")
	}
}

func TestBuildConntrackMatchersFromRulesFile(t *testing.T) {
	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "conntrack.toml")
	content := `[[all.matchers]]
protocol = "tcp"
orig_src_ip = "10.0.0.1"
orig_dst_port = 80

[[ipv4.matchers]]
zone = 7
reply_dst_ip = "10.0.0.3"

[[ipv6.matchers]]
protocol = "udp"
orig_dst_port = 53
`
	if err := os.WriteFile(rulesFile, []byte(content), 0o600); err != nil {
		t.Fatalf("write rules file: %v", err)
	}

	matcher, hasFilter, err := buildConntrackMatchers(nil, rulesFile)
	if err != nil {
		t.Fatalf("buildConntrackMatchers returned error: %v", err)
	}
	if !hasFilter {
		t.Fatalf("expected matcher to be built from rules file")
	}

	flow1 := makeConntrackFlow("10.0.0.1", "10.0.0.2", 12345, 80, unix.IPPROTO_TCP)
	if !matcher.MatchConntrackFlow(flow1) {
		t.Fatalf("expected first matcher from rules file to match")
	}

	flow2 := makeConntrackFlow("10.0.0.1", "10.0.0.2", 12345, 8080, unix.IPPROTO_TCP)
	flow2.Zone = 7
	flow2.Reverse.DstIP = net.ParseIP("10.0.0.3")
	if !matcher.MatchConntrackFlow(flow2) {
		t.Fatalf("expected second matcher from rules file to match")
	}

	if !matcher.MatchConntrackFlow(makeIPv6ConntrackFlow("2001:db8::1", "2001:db8::2", 12345, 53, unix.IPPROTO_UDP)) {
		t.Fatalf("expected ipv6 matcher from rules file to match")
	}

	if matcher.MatchConntrackFlow(makeConntrackFlow("10.0.0.1", "10.0.0.2", 12345, 53, unix.IPPROTO_UDP)) {
		t.Fatalf("did not expect ipv4 udp flow to match ipv6 matcher from rules file")
	}
}

func TestBuildConntrackMatchersFromRulesFileRejectsLegacyMatchersSection(t *testing.T) {
	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "conntrack.toml")
	content := `[[matchers]]
protocol = "tcp"
orig_dst_port = 80
`
	if err := os.WriteFile(rulesFile, []byte(content), 0o600); err != nil {
		t.Fatalf("write rules file: %v", err)
	}

	_, _, err := buildConntrackMatchers(nil, rulesFile)
	if err == nil {
		t.Fatalf("expected legacy [[matchers]] section to be rejected")
	}
}

func TestFormatConntrackFlowOVS(t *testing.T) {
	flow := makeConntrackFlow("10.0.0.1", "10.0.0.2", 12345, 80, unix.IPPROTO_TCP)
	flow.Zone = 7
	flow.Mark = 42
	flow.HasMark = true
	flow.Status = 0xe
	flow.HasStatus = true
	flow.TimeOut = 30
	flow.HasTimeout = true
	flow.Forward.Packets = 11
	flow.Forward.Bytes = 111
	flow.Reverse.Packets = 22
	flow.Reverse.Bytes = 222

	got := formatConntrackFlowOVS(flow, false)
	want := "tcp,orig=(src=10.0.0.1,dst=10.0.0.2,proto=tcp,sport=12345,dport=80,packets=11,bytes=111),reply=(src=10.0.0.2,dst=10.0.0.1,proto=tcp,sport=80,dport=12345,packets=22,bytes=222),zone=7,status=SEEN_REPLY|ASSURED|CONFIRMED,timeout=30,mark=42"
	if got != want {
		t.Fatalf("unexpected conntrack format:\n got: %s\nwant: %s", got, want)
	}
}

func TestFormatConntrackFlowOVS_ICMP(t *testing.T) {
	flow := &netlink.ConntrackFlow{
		FamilyType: unix.AF_INET,
		Zone:       9,
		Forward: netlink.IPTuple{
			SrcIP:    net.ParseIP("10.0.0.1"),
			DstIP:    net.ParseIP("10.0.0.2"),
			Protocol: unix.IPPROTO_ICMP,
			ICMPID:   10,
			ICMPType: 8,
			ICMPCode: 0,
			Packets:  1,
			Bytes:    64,
		},
		Reverse: netlink.IPTuple{
			SrcIP:    net.ParseIP("10.0.0.2"),
			DstIP:    net.ParseIP("10.0.0.1"),
			Protocol: unix.IPPROTO_ICMP,
			ICMPID:   10,
			ICMPType: 0,
			ICMPCode: 0,
			Packets:  1,
			Bytes:    64,
		},
	}

	got := formatConntrackFlowOVS(flow, false)
	want := "icmp,orig=(src=10.0.0.1,dst=10.0.0.2,proto=icmp,id=10,type=8,code=0,packets=1,bytes=64),reply=(src=10.0.0.2,dst=10.0.0.1,proto=icmp,id=10,type=0,code=0,packets=1,bytes=64),zone=9"
	if got != want {
		t.Fatalf("unexpected icmp conntrack format:\n got: %s\nwant: %s", got, want)
	}
}

func TestFormatConntrackFlowOVS_ICMPv6(t *testing.T) {
	flow := &netlink.ConntrackFlow{
		FamilyType: unix.AF_INET6,
		Zone:       3,
		Forward: netlink.IPTuple{
			SrcIP:    net.ParseIP("2001:db8::1"),
			DstIP:    net.ParseIP("2001:db8::2"),
			Protocol: unix.IPPROTO_ICMPV6,
			ICMPID:   10,
			ICMPType: 128,
			ICMPCode: 0,
		},
		Reverse: netlink.IPTuple{
			SrcIP:    net.ParseIP("2001:db8::2"),
			DstIP:    net.ParseIP("2001:db8::1"),
			Protocol: unix.IPPROTO_ICMPV6,
			ICMPID:   10,
			ICMPType: 129,
			ICMPCode: 0,
		},
	}

	got := formatConntrackFlowOVS(flow, false)
	want := "icmpv6,orig=(src=2001:db8::1,dst=2001:db8::2,proto=icmpv6,id=10,type=128,code=0,packets=0,bytes=0),reply=(src=2001:db8::2,dst=2001:db8::1,proto=icmpv6,id=10,type=129,code=0,packets=0,bytes=0),zone=3"
	if got != want {
		t.Fatalf("unexpected icmpv6 conntrack format:\n got: %s\nwant: %s", got, want)
	}
}

func TestFormatConntrackFlowOVSOrderMatchesOVSStyle(t *testing.T) {
	flow := makeConntrackFlow("10.0.0.1", "10.0.0.2", 12345, 80, unix.IPPROTO_TCP)
	flow.TimeStart = 1
	flow.TimeStop = 2
	flow.ID = 99
	flow.Zone = 7
	flow.Status = 0x1234
	flow.HasStatus = true
	flow.TimeOut = 30
	flow.HasTimeout = true
	flow.Mark = 42
	flow.HasMark = true
	flow.Labels = [16]byte{0xaa, 0xbb}
	flow.HasLabels = true
	flow.Use = 8

	got := formatConntrackFlowOVS(flow, false)

	assertBefore := func(a, b string) {
		aIdx := strings.Index(got, a)
		bIdx := strings.Index(got, b)
		if aIdx == -1 || bIdx == -1 {
			t.Fatalf("missing %q or %q in %q", a, b, got)
		}
		if aIdx >= bIdx {
			t.Fatalf("expected %q before %q in %q", a, b, got)
		}
	}

	assertBefore(",reply=(", ",start=")
	assertBefore(",start=", ",stop=")
	assertBefore(",stop=", ",id=")
	assertBefore(",id=", ",zone=")
	assertBefore(",zone=", ",status=")
	assertBefore(",status=", ",timeout=")
	assertBefore(",timeout=", ",mark=")
	assertBefore(",mark=", ",labels=")
	assertBefore(",labels=", ",use=")
}

func TestFormatConntrackFlowOVS_DecodeCTLabelAppendsDecodedFields(t *testing.T) {
	flow := makeConntrackFlow("10.0.0.1", "10.0.0.2", 12345, 80, unix.IPPROTO_TCP)
	flow.Zone = 7
	flow.Labels = [16]byte{
		0x01, 0x23, 0x45, 0x67,
		0x89, 0xab, 0xcd, 0xef,
		0x10, 0x32, 0x54, 0x76,
		0x98, 0xba, 0xdc, 0xfe,
	}
	flow.HasLabels = true

	got := formatConntrackFlowOVS(flow, true)

	assertContains := func(substr string) {
		if !strings.Contains(got, substr) {
			t.Fatalf("expected %q in %q", substr, got)
		}
	}

	assertContains(",labels=0xfedcba9876543210efcdab8967452301")
	assertContains(",label_round_number=0x1")
	assertContains(",label_origin_inport=43399")
	assertContains(",label_reply_inport=60875")
	assertContains(",label_encoding_scheme=micro segmentation")
	assertContains(",label_origin_packet_source=local bridge")
	assertContains(",label_reply_packet_source=0x01")
	assertContains(",label_monitor_policy_action_drop=true")
	assertContains(",label_work_policy_action_drop=true")

	if strings.Index(got, ",labels=") >= strings.Index(got, ",label_round_number=") {
		t.Fatalf("expected decoded ctlabel fields appended after labels: %q", got)
	}
}

func TestFormatConntrackLabelHexUsesDecodeCTLabelEndian(t *testing.T) {
	label := [16]byte{
		0x01, 0x23, 0x45, 0x67,
		0x89, 0xab, 0xcd, 0xef,
		0x10, 0x32, 0x54, 0x76,
		0x98, 0xba, 0xdc, 0xfe,
	}

	got := formatConntrackLabelHex(label)
	want := "fedcba9876543210efcdab8967452301"
	if got != want {
		t.Fatalf("unexpected conntrack label hex:\n got: %s\nwant: %s", got, want)
	}
}

func TestFormatConntrackStatus(t *testing.T) {
	if got, want := formatConntrackStatus(0xe), "SEEN_REPLY|ASSURED|CONFIRMED"; got != want {
		t.Fatalf("unexpected status format: got %q, want %q", got, want)
	}
	if got, want := formatConntrackStatus(1<<1|1<<14), "SEEN_REPLY|0x4000"; got != want {
		t.Fatalf("unexpected mixed status format: got %q, want %q", got, want)
	}
}

func TestConntrackCommandsDoNotExposeTopLevelFamilyFlag(t *testing.T) {
	for _, cmd := range []*cobra.Command{conntrackDumpCmd, conntrackDeleteCmd, conntrackUpdateCmd} {
		if flag := cmd.Flags().Lookup("family"); flag != nil {
			t.Fatalf("did not expect top-level --family on %q", cmd.Name())
		}
	}
}

func TestConntrackDumpCommandExposesDecodeFlag(t *testing.T) {
	if flag := conntrackDumpCmd.Flags().Lookup("decode"); flag == nil {
		t.Fatalf("expected top-level --decode on %q", conntrackDumpCmd.Name())
	} else if flag.Shorthand != "D" {
		t.Fatalf("expected --decode shorthand to be -D on %q", conntrackDumpCmd.Name())
	}
}

func TestConntrackCommandsExposeMatchersFileFlag(t *testing.T) {
	for _, cmd := range []*cobra.Command{conntrackDumpCmd, conntrackDeleteCmd} {
		if flag := cmd.Flags().Lookup("matchers-file"); flag == nil {
			t.Fatalf("expected top-level --matchers-file on %q", cmd.Name())
		}
		if flag := cmd.Flags().Lookup("rules-file"); flag != nil {
			t.Fatalf("did not expect legacy --rules-file on %q", cmd.Name())
		}
	}
}

func TestConntrackCommandsDoNotExposeTopLevelMatcherFlags(t *testing.T) {
	for _, cmd := range []*cobra.Command{conntrackDumpCmd, conntrackDeleteCmd, conntrackUpdateCmd} {
		for _, name := range []string{
			"zone",
			"protocol",
			"orig-src-ip",
			"src-ip",
			"orig-dst-ip",
			"dst-ip",
			"orig-src-port",
			"src-port",
			"orig-dst-port",
			"dst-port",
			"reply-src-ip",
			"reply-dst-ip",
			"reply-src-port",
			"reply-dst-port",
		} {
			if flag := cmd.Flags().Lookup(name); flag != nil {
				t.Fatalf("did not expect top-level --%s on %q", name, cmd.Name())
			}
		}
	}
}

func makeConntrackFlow(srcIP, dstIP string, srcPort, dstPort uint16, protocol uint8) *netlink.ConntrackFlow {
	src := net.ParseIP(srcIP)
	dst := net.ParseIP(dstIP)
	return &netlink.ConntrackFlow{
		FamilyType: unix.AF_INET,
		Forward: netlink.IPTuple{
			SrcIP:    src,
			DstIP:    dst,
			SrcPort:  srcPort,
			DstPort:  dstPort,
			Protocol: protocol,
		},
		Reverse: netlink.IPTuple{
			SrcIP:    dst,
			DstIP:    src,
			SrcPort:  dstPort,
			DstPort:  srcPort,
			Protocol: protocol,
		},
	}
}

func makeIPv6ConntrackFlow(srcIP, dstIP string, srcPort, dstPort uint16, protocol uint8) *netlink.ConntrackFlow {
	src := net.ParseIP(srcIP)
	dst := net.ParseIP(dstIP)
	return &netlink.ConntrackFlow{
		FamilyType: unix.AF_INET6,
		Forward: netlink.IPTuple{
			SrcIP:    src,
			DstIP:    dst,
			SrcPort:  srcPort,
			DstPort:  dstPort,
			Protocol: protocol,
		},
		Reverse: netlink.IPTuple{
			SrcIP:    dst,
			DstIP:    src,
			SrcPort:  dstPort,
			DstPort:  srcPort,
			Protocol: protocol,
		},
	}
}

func makeICMPConntrackFlow(srcIP, dstIP string, protocol uint8) *netlink.ConntrackFlow {
	src := net.ParseIP(srcIP)
	dst := net.ParseIP(dstIP)
	return &netlink.ConntrackFlow{
		FamilyType: unix.AF_INET,
		Forward: netlink.IPTuple{
			SrcIP:    src,
			DstIP:    dst,
			Protocol: protocol,
		},
		Reverse: netlink.IPTuple{
			SrcIP:    dst,
			DstIP:    src,
			Protocol: protocol,
		},
	}
}
