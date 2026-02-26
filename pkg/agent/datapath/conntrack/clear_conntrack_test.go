//go:build linux

package conntrack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	netlink "github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
	"k8s.io/klog"

	"github.com/everoute/everoute/pkg/constants"
)

const (
	// TEST_ZONE must be in [CTZoneForPolicyMin, CTZoneForPolicyMax] (0x8000..0xcfff)
	// or matcherBatch.MatchConntrackFlow() filters out all flows and no update is triggered.
	TEST_ZONE = constants.CTZoneForPolicyMin
	// Default timeout (seconds) for manually created conntrack entries.
	// Kernel may reject TimeOut=0; use a positive value (e.g. UDP default 60).
	CONNTRACK_DEFAULT_TIMEOUT_SEC = 360
	// IPS_CONFIRMED: kernel sets this before parsing CTA_STATUS; if we send Status=0,
	// nf_ct_change_status_common() rejects clearing it with -EBUSY (see nf_conntrack_core.c).
	// Must send at least IPS_CONFIRMED when creating. Value from uapi/linux/netfilter/nf_conntrack_common.h.
	IPS_CONFIRMED = 1 << 3
	// conntrackMaxDesired: set nf_conntrack_max to at least this so benchmarks can create 1000000+ flows.
	conntrackMaxDesired = 2000000
)

const nfConntrackMaxPath = "/proc/sys/net/netfilter/nf_conntrack_max"

// setConntrackMaxToAtLeast sets nf_conntrack_max to at least min (requires root). Idempotent.
func setConntrackMaxToAtLeast(min int) {
	b, err := os.ReadFile(nfConntrackMaxPath)
	if err != nil {
		return
	}
	n, err := strconv.Atoi(string(bytesTrimNewline(b)))
	if err != nil || n >= min {
		return
	}
	_ = os.WriteFile(nfConntrackMaxPath, []byte(strconv.Itoa(min)+"\n"), 0o200)
}

// dumpAndFindFlowByTuple dumps conntrack table and returns the flow matching zone and forward tuple.
func dumpAndFindFlowByTuple(family uint8, zone uint16, forward *netlink.IPTuple) *netlink.ConntrackFlow {
	flowChan := make(chan *netlink.ConntrackFlow, 10000)
	go func() {
		defer func() { flowChan <- nil }()
		_ = netlink.ConntrackTableListStream(netlink.ConntrackTable, netlink.InetFamily(family), flowChan, func() *netlink.ConntrackFlow {
			return &netlink.ConntrackFlow{}
		})
	}()
	for f := range flowChan {
		if f == nil {
			break
		}
		if f.Zone == zone && tuplesEqual(&f.Forward, forward) {
			return f
		}
	}
	return nil
}

func TestCreateAndUpdateConntrackFlow(t *testing.T) {
	defer clearAllConntrackFlows()
	clearAllConntrackFlows()
	// Use non-zero initial labels so we can verify the update actually changed them in kernel
	initialLabels := [16]byte{0x12, 0x34}
	var flow netlink.ConntrackFlow
	initConntrackFlow(&flow, TEST_ZONE, unix.AF_INET, net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.2"), 80, 80, unix.IPPROTO_TCP, initialLabels, true, 0, 0, 0)
	err := netlink.ConntrackCreate(netlink.ConntrackTable, netlink.InetFamily(unix.AF_INET), &flow)
	if err != nil {
		t.Skipf("conntrack create failed (may need root): %v", err)
	}
	// First dump: verify initial labels, then update
	found := dumpAndFindFlowByTuple(unix.AF_INET, flow.Zone, &flow.Forward)
	if found == nil {
		t.Fatalf("conntrack flow not found after create")
	}
	if !found.HasLabels {
		t.Fatalf("conntrack flow has no labels, flow: %s", found.String())
	}
	if !bytes.Equal(found.Labels[:], initialLabels[:]) {
		t.Fatalf("conntrack flow labels mismatch before update, expect: %x, actual: %x", initialLabels, found.Labels)
	}
	// Update: clear bits 1 and 4 of byte 0 via LabelsMask
	found.Labels = [16]byte{}
	found.LabelsMask = [16]byte{}
	found.LabelsMask[0] = 0x12
	if err = netlink.ConntrackUpdate(netlink.ConntrackTable, netlink.InetFamily(unix.AF_INET), found); err != nil {
		t.Fatalf("update conntrack flow error, err: %v", err)
	}
	// Second dump: verify labels actually changed in kernel
	time.Sleep(50 * time.Millisecond)
	foundAfter := dumpAndFindFlowByTuple(unix.AF_INET, flow.Zone, &flow.Forward)
	if foundAfter == nil {
		t.Fatalf("conntrack flow not found after update")
	}
	if (foundAfter.Labels[0] & 0x12) != 0 {
		t.Fatalf("labels[0] bits 0x12 should be cleared after update, got: %x", foundAfter.Labels[0])
	}
}

// TestCreateAndUpdateConntrackFlow_Protocols tests create, dump, update, and verify label change
// for each protocol. Requires root and linux.
func TestCreateAndUpdateConntrackFlow_Protocols(t *testing.T) {
	initialLabels := [16]byte{0xAA, 0xBB}
	testCases := []struct {
		name     string
		family   uint8
		protocol uint8
		srcIP    string
		dstIP    string
		srcPort  uint16
		dstPort  uint16
		icmpID   uint16
		icmpType uint8
		icmpCode uint8
	}{
		{"IPv4_TCP", unix.AF_INET, unix.IPPROTO_TCP, "192.168.10.1", "192.168.10.2", 12345, 80, 0, 0, 0},
		{"IPv4_UDP", unix.AF_INET, unix.IPPROTO_UDP, "192.168.10.3", "192.168.10.4", 54321, 53, 0, 0, 0},
		{"IPv4_ICMP", unix.AF_INET, unix.IPPROTO_ICMP, "192.168.10.5", "192.168.10.6", 0, 0, 1, 8, 0},
		{"IPv4_GRE", unix.AF_INET, unix.IPPROTO_GRE, "192.168.10.7", "192.168.10.8", 0, 0, 0, 0, 0},
		{"IPv4_IPIP", unix.AF_INET, unix.IPPROTO_IPIP, "192.168.10.9", "192.168.10.10", 0, 0, 0, 0, 0},
		{"IPv6_TCP", unix.AF_INET6, unix.IPPROTO_TCP, "2001:db8::1", "2001:db8::2", 12345, 443, 0, 0, 0},
		{"IPv6_UDP", unix.AF_INET6, unix.IPPROTO_UDP, "2001:db8::3", "2001:db8::4", 54321, 53, 0, 0, 0},
		{"IPv6_ICMPv6", unix.AF_INET6, unix.IPPROTO_ICMPV6, "2001:db8::5", "2001:db8::6", 0, 0, 1, 128, 0},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defer clearAllConntrackFlows()
			clearAllConntrackFlows()
			time.Sleep(50 * time.Millisecond)
			srcIP := net.ParseIP(tc.srcIP)
			dstIP := net.ParseIP(tc.dstIP)
			if srcIP == nil || dstIP == nil {
				t.Fatalf("invalid IP: %s, %s", tc.srcIP, tc.dstIP)
			}
			var flow netlink.ConntrackFlow
			initConntrackFlow(&flow, TEST_ZONE, tc.family, srcIP, dstIP, tc.srcPort, tc.dstPort, tc.protocol,
				initialLabels, true, tc.icmpID, tc.icmpType, tc.icmpCode)
			err := netlink.ConntrackCreate(netlink.ConntrackTable, netlink.InetFamily(tc.family), &flow)
			if err != nil {
				t.Skipf("conntrack create failed (may need root or kernel support): %v", err)
			}
			found := dumpAndFindFlowByTuple(tc.family, flow.Zone, &flow.Forward)
			if found == nil {
				t.Fatalf("flow not found after create")
			}
			if !found.HasLabels || !bytes.Equal(found.Labels[:], initialLabels[:]) {
				t.Fatalf("labels mismatch before update: hasLabels=%v, labels=%x", found.HasLabels, found.Labels)
			}
			found.Labels = [16]byte{}
			found.LabelsMask = [16]byte{}
			found.LabelsMask[0] = 0xFF
			if err = netlink.ConntrackUpdate(netlink.ConntrackTable, netlink.InetFamily(tc.family), found); err != nil {
				t.Fatalf("update failed: %v", err)
			}
			time.Sleep(50 * time.Millisecond)
			foundAfter := dumpAndFindFlowByTuple(tc.family, flow.Zone, &flow.Forward)
			if foundAfter == nil {
				t.Fatalf("flow not found after update")
			}
			if (foundAfter.Labels[0] & 0xFF) != 0 {
				t.Fatalf("labels[0] should be cleared after update, got: %x", foundAfter.Labels[0])
			}
		})
	}
}

// TestUpdateConntrackFlows_MatchAndUpdate verifies that UpdateConntrackFlows can match a real CT
// flow and update its labels. Creates flow, builds Matcher from it, calls UpdateConntrackFlows,
// then dumps to verify labels changed.
func TestUpdateConntrackFlows_MatchAndUpdate(t *testing.T) {
	defer clearAllConntrackFlows()
	clearAllConntrackFlows()
	time.Sleep(50 * time.Millisecond)
	initialLabels := [16]byte{0x11, 0x22, 0x33}
	var flow netlink.ConntrackFlow
	initConntrackFlow(&flow, TEST_ZONE, unix.AF_INET, net.ParseIP("192.168.20.1"), net.ParseIP("192.168.20.2"),
		9999, 8080, unix.IPPROTO_TCP, initialLabels, true, 0, 0, 0)
	err := netlink.ConntrackCreate(netlink.ConntrackTable, netlink.InetFamily(unix.AF_INET), &flow)
	if err != nil {
		t.Skipf("conntrack create failed (may need root): %v", err)
	}
	matcher := Matcher{
		ID:             "test-match",
		SrcIP:          netIPTo16(flow.Forward.SrcIP),
		SrcIPPrefixLen: 128,
		DstIP:          netIPTo16(flow.Forward.DstIP),
		DstIPPrefixLen: 128,
		IPProtocol:     unix.IPPROTO_TCP,
		SrcPort:        9999,
		SrcPortMask:    0xffff,
		DstPort:        8080,
		DstPortMask:    0xffff,
	}
	matchers := CookMatcherBatch([]Matcher{matcher})
	pool := sync.Pool{New: func() any { return &netlink.ConntrackFlow{} }}
	allocator := func() *netlink.ConntrackFlow { return pool.Get().(*netlink.ConntrackFlow) }
	deallocator := func(f *netlink.ConntrackFlow) { pool.Put(f) }
	updateFunc := func(f *netlink.ConntrackFlow) bool {
		if !f.HasLabels {
			return false
		}
		f.Labels = [16]byte{}
		f.LabelsMask = [16]byte{}
		f.LabelsMask[0] = 0xFF
		return true
	}
	dumpCount, matchCount, successCount, failureCount, err := UpdateConntrackFlows(unix.AF_INET, matchers, allocator, deallocator, updateFunc)
	if err != nil {
		t.Fatalf("UpdateConntrackFlows failed: %v", err)
	}
	if matchCount < 1 {
		t.Fatalf("expected matchCount >= 1, got dump=%d match=%d success=%d failure=%d", dumpCount, matchCount, successCount, failureCount)
	}
	if successCount < 1 && failureCount > 0 {
		t.Fatalf("update failed: match=%d success=%d failure=%d", matchCount, successCount, failureCount)
	}
	time.Sleep(50 * time.Millisecond)
	foundAfter := dumpAndFindFlowByTuple(unix.AF_INET, flow.Zone, &flow.Forward)
	if foundAfter == nil {
		t.Fatalf("flow not found after UpdateConntrackFlows")
	}
	if (foundAfter.Labels[0] & 0xFF) != 0 {
		t.Fatalf("labels[0] should be cleared by UpdateConntrackFlows, got: %x", foundAfter.Labels[0])
	}
}

// tuplesEqual reports whether two IPTuples match by SrcIP, DstIP, SrcPort, DstPort, Protocol.
// For ICMP and ICMPv6, also compares ICMPID, ICMPType, ICMPCode.
func tuplesEqual(a, b *netlink.IPTuple) bool {
	if a == nil || b == nil {
		return a == b
	}
	if !(a.SrcIP == nil && b.SrcIP == nil || a.SrcIP != nil && b.SrcIP != nil && a.SrcIP.Equal(b.SrcIP)) {
		return false
	}
	if !(a.DstIP == nil && b.DstIP == nil || a.DstIP != nil && b.DstIP != nil && a.DstIP.Equal(b.DstIP)) {
		return false
	}
	if a.SrcPort != b.SrcPort || a.DstPort != b.DstPort || a.Protocol != b.Protocol {
		return false
	}
	if a.Protocol == unix.IPPROTO_ICMP || a.Protocol == unix.IPPROTO_ICMPV6 {
		return a.ICMPID == b.ICMPID && a.ICMPType == b.ICMPType && a.ICMPCode == b.ICMPCode
	}
	return true
}

func bytesTrimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

func clearAllConntrackFlows() {
	netlink.ConntrackTableFlush(netlink.ConntrackTable)
}

// var globalConntrackPool = sync.Pool{
// 	New: func() any {
// 		return &netlink.ConntrackFlow{}
// 	},
// }

const (
	mtN         = 624
	mtM         = 397
	mtMatrixA   = 0x9908b0df
	mtUpperMask = 0x80000000
	mtLowerMask = 0x7fffffff
)

var (
	mtState [mtN]uint32
	mtIndex int
	mtInit  bool
)

func init() {
	klog.InitFlags(nil)
	initMT19937(5489)
	_ = randU32()
	setConntrackMaxToAtLeast(conntrackMaxDesired)
}

func initMT19937(seed uint32) {
	mtState[0] = seed
	for i := 1; i < mtN; i++ {
		mtState[i] = 1812433253*(mtState[i-1]^(mtState[i-1]>>30)) + uint32(i)
	}
	mtIndex = 0
	mtInit = true
}

func randU32() uint32 {
	return randMT19937()
}

func randU64() uint64 {
	return uint64(randMT19937())<<32 | uint64(randMT19937())
}

// fastly than crypto/rand.Read
func randMT19937() uint32 {
	if !mtInit {
		initMT19937(5489)
	}

	if mtIndex >= mtN {
		generateMT19937Numbers()
		mtIndex = 0
	}

	y := mtState[mtIndex]
	mtIndex++

	y ^= (y >> 11)
	y ^= (y << 7) & 0x9d2c5680
	y ^= (y << 15) & 0xefc60000
	y ^= (y >> 18)

	return y
}

func generateMT19937Numbers() {
	var y uint32
	for i := 0; i < mtN; i++ {
		y = (mtState[i] & mtUpperMask) + (mtState[(i+1)%mtN] & mtLowerMask)
		mtState[i] = mtState[(i+mtM)%mtN] ^ (y >> 1)
		if y%2 != 0 {
			mtState[i] ^= mtMatrixA
		}
	}
}

// initConntrackFlow initializes a conntrack flow for create. For TCP/UDP use srcPort,dstPort;
// for ICMP/ICMPv6 use icmpID,icmpType,icmpCode (srcPort,dstPort must be 0);
// for GRE/IPIP use srcPort=0,dstPort=0, icmpID=0,icmpType=0,icmpCode=0.
func initConntrackFlow(flow *netlink.ConntrackFlow,
	zone uint16, familyType uint8,
	srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8,
	labels [16]byte, hasLabels bool,
	icmpID uint16, icmpType, icmpCode uint8) {
	if srcIP == nil {
		panic("srcIP is nil")
	}
	if dstIP == nil {
		panic("dstIP is nil")
	}
	if protocol != unix.IPPROTO_TCP && protocol != unix.IPPROTO_UDP {
		if srcPort != 0 || dstPort != 0 {
			panic("srcPort/dstPort must be 0 when protocol is not TCP or UDP")
		}
	}
	flow.FamilyType = familyType
	flow.Forward = netlink.IPTuple{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: protocol,
	}
	flow.Reverse = netlink.IPTuple{
		SrcIP:    dstIP,
		DstIP:    srcIP,
		SrcPort:  dstPort,
		DstPort:  srcPort,
		Protocol: protocol,
	}
	if protocol == unix.IPPROTO_ICMP || protocol == unix.IPPROTO_ICMPV6 {
		flow.Forward.ICMPID = icmpID
		flow.Forward.ICMPType = icmpType
		flow.Forward.ICMPCode = icmpCode
		flow.Reverse.ICMPID = icmpID
		// ICMP echo request (8) -> reply (0); ICMPv6 echo request (128) -> reply (129)
		if icmpType == 8 {
			flow.Reverse.ICMPType = 0
		} else if icmpType == 128 {
			flow.Reverse.ICMPType = 129
		} else {
			flow.Reverse.ICMPType = 0
		}
		flow.Reverse.ICMPCode = 0
	}
	flow.Mark = 0
	flow.Zone = zone
	flow.TimeStart = 0
	flow.TimeStop = 0
	flow.TimeOut = CONNTRACK_DEFAULT_TIMEOUT_SEC
	flow.Status = IPS_CONFIRMED
	flow.Use = 0
	flow.Labels = labels
	flow.HasLabels = hasLabels
	if protocol == unix.IPPROTO_TCP {
		flow.ProtoInfo = &netlink.ProtoInfoTCP{
			State:          nl.TCP_CONNTRACK_ESTABLISHED,
			WsacleOriginal: 10,
			WsacleReply:    10,
			FlagsOriginal:  10,
			FlagsReply:     10,
		}
	}
}

func initRandomConntrackFlow(flow *netlink.ConntrackFlow, zone uint16, familyType uint8, labels [16]byte, hasLabels bool) {
	var srcIP, dstIP net.IP
	switch familyType {
	case unix.AF_INET:
		srcIPInt := randU32()
		dstIPInt := randU32()
		srcIP = (net.IP)([]byte{
			byte(srcIPInt >> 24), byte(srcIPInt >> 16), byte(srcIPInt >> 8), byte(srcIPInt),
		})
		dstIP = (net.IP)([]byte{
			byte(dstIPInt >> 24), byte(dstIPInt >> 16), byte(dstIPInt >> 8), byte(dstIPInt),
		})
	case unix.AF_INET6:
		srcIPIntHigh := randU64()
		srcIPIntLow := randU64()
		dstIPIntHigh := randU64()
		dstIPIntLow := randU64()
		srcIP = (net.IP)([]byte{
			byte(srcIPIntLow >> 56), byte(srcIPIntLow >> 48), byte(srcIPIntLow >> 40), byte(srcIPIntLow >> 32),
			byte(srcIPIntLow >> 24), byte(srcIPIntLow >> 16), byte(srcIPIntLow >> 8), byte(srcIPIntLow),
			byte(srcIPIntHigh >> 56), byte(srcIPIntHigh >> 48), byte(srcIPIntHigh >> 40), byte(srcIPIntHigh >> 32),
			byte(srcIPIntHigh >> 24), byte(srcIPIntHigh >> 16), byte(srcIPIntHigh >> 8), byte(srcIPIntHigh),
		})
		dstIP = (net.IP)([]byte{
			byte(dstIPIntLow >> 56), byte(dstIPIntLow >> 48), byte(dstIPIntLow >> 40), byte(dstIPIntLow >> 32),
			byte(dstIPIntLow >> 24), byte(dstIPIntLow >> 16), byte(dstIPIntLow >> 8), byte(dstIPIntLow),
			byte(dstIPIntHigh >> 56), byte(dstIPIntHigh >> 48), byte(dstIPIntHigh >> 40), byte(dstIPIntHigh >> 32),
			byte(dstIPIntHigh >> 24), byte(dstIPIntHigh >> 16), byte(dstIPIntHigh >> 8), byte(dstIPIntHigh),
		})
	default:
		panic("unsupported family type")
	}
	randPorts := randU32()
	srcPort := uint16(randPorts & 0xFFFF)
	dstPort := uint16((randPorts >> 16) & 0xFFFF)
	protocol := uint8(unix.IPPROTO_TCP)
	if randU32()%2 == 0 {
		protocol = unix.IPPROTO_UDP
	}
	initConntrackFlow(
		flow, zone, familyType,
		srcIP, dstIP, srcPort, dstPort, protocol,
		labels, hasLabels, 0, 0, 0)
}

// initRandomConntrackFlows flushes the conntrack table and creates the given flows.
func initRandomConntrackFlows(familyType uint8, conntrackFlows []netlink.ConntrackFlow) {
	clearAllConntrackFlows()
	// Allow kernel to finish flush; immediate create can return EBUSY on some systems.
	time.Sleep(100 * time.Millisecond)
	rtAttrs := make([]*nl.RtAttr, 0)
	handle, err := netlink.NewHandle(unix.NETLINK_NETFILTER)
	if err != nil {
		panic(fmt.Sprintf("failed to create netlink handle, err: %s", err))
	}
	defer handle.Close()
	rtAttrIndex := 0
	request := handle.NewConntrackCreateRequest(netlink.ConntrackTable, netlink.InetFamily(familyType), true)
	buffer := make([]nl.NetlinkRequestData, 32)
	for i := 0; i < len(conntrackFlows); i++ {
		rtAttrIndex = 0
		newRtAttr := func(attrType int, data []byte) *nl.RtAttr {
			if rtAttrIndex >= len(rtAttrs) {
				rtAttr := nl.NewRtAttr(attrType, data)
				rtAttrs = append(rtAttrs, rtAttr)
				rtAttrIndex++
				return rtAttr
			}
			attr := rtAttrs[rtAttrIndex]
			*attr = nl.RtAttr{}
			attr.RtAttr.Type = uint16(attrType)
			attr.Data = data
			rtAttrIndex++
			return attr
		}
		err := handle.ExecuteConntrackRequest(request, &conntrackFlows[i], newRtAttr, buffer, true)
		if err != nil {
			jFlow, _ := json.Marshal(conntrackFlows[i])
			panic(fmt.Sprintf("failed to create the %dth conntrack flow, family type: %d, flow: %s, err: %s", i, familyType, string(jFlow), err))
		}
	}
}

// netIPTo16 converts net.IP to [16]byte (IPv4-mapped for IPv4).
func netIPTo16(ip net.IP) [16]byte {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return [16]byte{}
	}
	return addr.As16()
}

func randomMatchersFromFlows(flows []netlink.ConntrackFlow, count int) MatcherBatch {
	matchers := make([]Matcher, 0, count)
	randomFlows := make([]int, len(flows))
	for i := 0; i < len(randomFlows); i++ {
		randomFlows[i] = i
	}
	for i := 0; i < len(randomFlows); i++ {
		randomIndex := int(randU64() & ^(uint64(1)<<63)) % len(randomFlows)
		randomFlows[i], randomFlows[randomIndex] = randomFlows[randomIndex], randomFlows[i]
	}
	// IP is stored as 16-byte (IPv4-mapped for IPv4), use full 128 bits for exact match
	prefixLen := 128
	if count <= len(flows) {
		// Each matcher corresponds to a different flow (sampling without replacement).
		for i := 0; i < count; i++ {
			f := flows[randomFlows[i]].Forward
			srcIP := netIPTo16(f.SrcIP)
			dstIP := netIPTo16(f.DstIP)
			matcher := Matcher{
				ID:             fmt.Sprintf("from-%d", randomFlows[i]),
				IPFamily:       flows[randomFlows[i]].FamilyType,
				IPProtocol:     f.Protocol,
				SrcIP:          srcIP,
				DstIP:          dstIP,
				SrcIPPrefixLen: prefixLen,
				DstIPPrefixLen: prefixLen,
				SrcPort:        f.SrcPort,
				DstPort:        f.DstPort,
			}
			matchers = append(matchers, matcher)
		}
	} else {
		// More matchers than flows: assign one matcher per flow first so all flows are covered,
		// then add the rest randomly (with replacement) to reach count.
		for i := 0; i < len(randomFlows); i++ {
			f := flows[randomFlows[i]].Forward
			srcIP := netIPTo16(f.SrcIP)
			dstIP := netIPTo16(f.DstIP)
			matcher := Matcher{
				ID:             fmt.Sprintf("from-%d", randomFlows[i]),
				IPFamily:       flows[randomFlows[i]].FamilyType,
				IPProtocol:     f.Protocol,
				SrcIP:          srcIP,
				DstIP:          dstIP,
				SrcIPPrefixLen: prefixLen,
				DstIPPrefixLen: prefixLen,
				SrcPort:        f.SrcPort,
				DstPort:        f.DstPort,
			}
			matchers = append(matchers, matcher)
		}
		for i := len(randomFlows); i < count; i++ {
			randomIndex := int(randU64() & ^(uint64(1)<<63)) % len(randomFlows)
			f := flows[randomFlows[randomIndex]].Forward
			srcIP := netIPTo16(f.SrcIP)
			dstIP := netIPTo16(f.DstIP)
			matcher := Matcher{
				ID:             fmt.Sprintf("from-%d-extra-%d", randomFlows[randomIndex], i),
				IPFamily:       flows[randomFlows[randomIndex]].FamilyType,
				IPProtocol:     f.Protocol,
				SrcIP:          srcIP,
				DstIP:          dstIP,
				SrcIPPrefixLen: prefixLen,
				DstIPPrefixLen: prefixLen,
				SrcPort:        f.SrcPort,
				DstPort:        f.DstPort,
			}
			matchers = append(matchers, matcher)
		}
	}
	return CookMatcherBatch(matchers)
}

func prepareFlowsAndMatchers(zone uint16, ipFamily uint8, flowCount int, matcherCount int, ctlabels [16]byte, hasLabels bool) ([]netlink.ConntrackFlow, MatcherBatch) {
	flows := make([]netlink.ConntrackFlow, flowCount)
	for i := 0; i < flowCount; i++ {
		initRandomConntrackFlow(&flows[i], zone, ipFamily, ctlabels, hasLabels)
	}
	matchers := randomMatchersFromFlows(flows, matcherCount)
	return flows, matchers
}

const (
	EgressTreatedXXREG0Bit  = 6
	IngressTreatedXXREG0Bit = 7
)

func doBenchmarkClearConntrackFlows(b *testing.B, zone uint16, ipFamily uint8, flowCount int, matcherCount int, initCtlabels [16]byte,
	allocator func() *netlink.ConntrackFlow, deallocator func(*netlink.ConntrackFlow)) {
	flows, matchers := prepareFlowsAndMatchers(zone, ipFamily, flowCount, matcherCount, initCtlabels, true)
	clearAllConntrackFlows()
	initRandomConntrackFlows(ipFamily, flows)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// expect skipped count is zero,
		// but it may be non-zero due to kernel/netlink behavior variations
		skippedCount := 0
		unsetTreatedRegs := func(flow *netlink.ConntrackFlow) (updated bool) {
			if !flow.HasLabels {
				skippedCount++
				return false
			}
			flow.Labels = [16]byte{}
			flow.LabelsMask = [16]byte{}
			flow.LabelsMask[0] = 1<<EgressTreatedXXREG0Bit | 1<<IngressTreatedXXREG0Bit
			return true
		}
		dumpCount, matchCount, successCount, failureCount, err := UpdateConntrackFlows(ipFamily, matchers, allocator, deallocator, unsetTreatedRegs)
		if err != nil {
			b.Fatalf("clear conntrack worker error, family: %d, err: %v", ipFamily, err)
		}
		// klog.Infof("clear conntrack worker, family: %d, dump: %d, match: %d, success: %d, failure: %d, matchers: %d, flows: %d", ipFamily, dumpCount, matchCount, successCount, failureCount, len(matchers), len(flows))
		if matchCount == 0 || successCount+skippedCount == 0 || failureCount > 0 {
			b.Fatalf("clear conntrack worker error, family: %d, dump: %d, match: %d, success: %d, failure: %d, skipped: %d", ipFamily, dumpCount, matchCount, successCount, failureCount, skippedCount)
		}
		klog.V(1).Infof("clear conntrack worker, family: %d, dump: %d, match: %d, success: %d, failure: %d, skipped: %d, matchers: %d, flows: %d", ipFamily, dumpCount, matchCount, successCount, failureCount, skippedCount, len(matchers.IDs), len(flows))
	}
}

func BenchmarkClearConntrackFlowsIPv4(b *testing.B) {
	matcherCounts := []int{1, 10, 100, 1000, 10000, 100000}
	flowCounts := []int{1, 10, 100, 1000, 10000, 100000, 1000000}
	pool := sync.Pool{
		New: func() any {
			return &netlink.ConntrackFlow{}
		},
	}
	allocator := func() *netlink.ConntrackFlow {
		return pool.Get().(*netlink.ConntrackFlow)
	}
	deallocator := func(flow *netlink.ConntrackFlow) {
		pool.Put(flow)
	}
	labels := [16]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	for _, matcherCount := range matcherCounts {
		for _, flowCount := range flowCounts {
			if matcherCount > flowCount {
				continue
			}
			for i := 0; i < 10000; i++ {
				deallocator(allocator())
			}
			b.Run(fmt.Sprintf("%d matchers %d flows", matcherCount, flowCount), func(b *testing.B) {
				b.ReportAllocs()
				doBenchmarkClearConntrackFlows(b, TEST_ZONE, unix.AF_INET, flowCount, matcherCount, labels, allocator, deallocator)
			})
		}
	}
}

func BenchmarkClearConntrackFlowsIPv6(b *testing.B) {
	matcherCounts := []int{1, 10, 100, 1000, 10000, 100000}
	flowCounts := []int{1, 10, 100, 1000, 10000, 100000, 1000000}
	labels := [16]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	pool := sync.Pool{
		New: func() any {
			return &netlink.ConntrackFlow{}
		},
	}
	allocator := func() *netlink.ConntrackFlow {
		return pool.Get().(*netlink.ConntrackFlow)
	}
	deallocator := func(flow *netlink.ConntrackFlow) {
		pool.Put(flow)
	}
	for _, matcherCount := range matcherCounts {
		for _, flowCount := range flowCounts {
			if matcherCount > flowCount {
				continue
			}
			for i := 0; i < 10000; i++ {
				deallocator(allocator())
			}
			b.Run(fmt.Sprintf("%d matchers %d flows", matcherCount, flowCount), func(b *testing.B) {
				b.ReportAllocs()
				doBenchmarkClearConntrackFlows(b, TEST_ZONE, unix.AF_INET6, flowCount, matcherCount, labels, allocator, deallocator)
			})
		}
	}
}
