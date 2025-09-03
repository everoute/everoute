package erctl

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/ti-mo/conntrack"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/everoute/everoute/pkg/apis/rpc/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	"github.com/everoute/everoute/pkg/utils"
)

var (
	ruleconn    v1alpha1.GetterClient
	cnt         map[uint64][]tuple
	showCTflows bool
)

type Rule struct {
	*v1alpha1.RuleEntry
	Count   int     `json:"Count,omitempty"`
	CTFlows []tuple `json:"CTFlows,omitempty"`
}

func ConnectClient() error {
	rpc, err := grpc.Dial(constants.RPCSocketAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
			unixAddr, _ := net.ResolveUnixAddr("unix", constants.RPCSocketAddr)
			connUnix, err := net.DialUnix("unix", nil, unixAddr)
			return connUnix, err
		}))
	if err != nil {
		return err
	}
	ruleconn = v1alpha1.NewGetterClient(rpc)
	return nil
}

func ConnectRule(show bool) error {
	showCTflows = show
	if err := ConnectClient(); err != nil {
		return err
	}
	ct, err := conntrack.Dial(nil)
	if err != nil {
		return err
	}
	cnt = map[uint64][]tuple{}
	flows, err := ct.Dump()
	if err != nil {
		return err
	}
	parseFlows(flows)

	return err
}

func GetAllRules() ([]*Rule, error) {
	ruleEntries, err := ruleconn.GetAllRules(context.Background(), &emptypb.Empty{})
	if err != nil {
		return nil, err
	}
	rules := rpcRuleAddCount(ruleEntries.RuleEntries)
	return rules, nil
}

func GetRulesByName(ruleIDs []string) ([]*Rule, error) {
	ruleEntries, err := ruleconn.GetRulesByName(context.Background(), &v1alpha1.RuleIDs{RuleIDs: ruleIDs})
	if err != nil {
		return nil, err
	}
	rules := rpcRuleAddCount(ruleEntries.RuleEntries)
	return rules, nil
}

func GetRulesByFlow(flowIDs []int64) ([]*Rule, error) {
	fids := make([]uint64, len(flowIDs))
	for i := 0; i < len(flowIDs); i++ {
		fids[i] = uint64(flowIDs[i])
	}
	ruleEntries, err := ruleconn.GetRulesByFlow(context.Background(), &v1alpha1.FlowIDs{FlowIDs: fids})
	if err != nil {
		return nil, err
	}
	rules := rpcRuleAddCount(ruleEntries.RuleEntries)
	return rules, nil
}

func GetSvcInfoBySvcID(svcID string) (*v1alpha1.SvcInfo, error) {
	return ruleconn.GetSvcInfoBySvcID(context.Background(), &v1alpha1.SvcID{ID: svcID})
}

func GetTRRulesByFlowIDs(flowIDs []int64) (*v1alpha1.TRRules, error) {
	p := []uint64{}
	for i := range flowIDs {
		p = append(p, uint64(flowIDs[i]))
	}
	return ruleconn.GetTRRulesByFlowIDs(context.Background(), &v1alpha1.FlowIDs{FlowIDs: p})
}

func GetTRRulesByKeys(ks []string) (*v1alpha1.TRRules, error) {
	return ruleconn.GetTRRulesByRuleKeys(context.Background(), &v1alpha1.TRRuleKeys{TRRuleKeys: ks})
}

type tuple struct {
	srcIP, dstIP, status string
	srcPort, dstPort     uint32
	protocol             uint32
}

func (t tuple) MarshalJSON() ([]byte, error) {
	s := fmt.Sprintf(`"SrcIP:%s, DstIP:%s, SrcPort:%d, DstPort:%d, Protocol:%d, status:%s"`,
		t.srcIP, t.dstIP, t.srcPort, t.dstPort, t.protocol, t.status)
	return []byte(s), nil
}

func parseFlows(flows []conntrack.Flow) {
	for _, flow := range flows {
		if len(flow.Labels) == 0 {
			continue
		}
		origTuple := tuple{
			srcIP:    flow.TupleOrig.IP.SourceAddress.String(),
			dstIP:    flow.TupleOrig.IP.DestinationAddress.String(),
			srcPort:  uint32(flow.TupleOrig.Proto.SourcePort),
			dstPort:  uint32(flow.TupleOrig.Proto.DestinationPort),
			protocol: uint32(flow.TupleOrig.Proto.Protocol),
			status:   flow.Status.String(),
		}
		u1, u2, u3 := utils.CtLabelDecode(flow.Labels)
		addCnt(origTuple, u1, u2, u3)
	}
}

func addCnt(tp tuple, indexes ...uint64) {
	for _, index := range indexes {
		if index == 0 {
			continue
		}
		if _, ok := cnt[index]; !ok {
			cnt[index] = []tuple{tp}
			continue
		}
		cnt[index] = append(cnt[index], tp)
	}
}

func rpcRuleAddCount(rpcRule []*v1alpha1.RuleEntry) []*Rule {
	rule := make([]*Rule, len(rpcRule))

	for i, entry := range rpcRule {
		ctf := []tuple{}
		for _, flowEntry := range entry.RuleFlowMap {
			if _, ok := cnt[flowEntry.FlowID]; ok {
				ctf = append(ctf, cnt[flowEntry.FlowID]...)
			}
		}

		rule[i] = &Rule{
			RuleEntry: entry,
			Count:     len(ctf),
			CTFlows:   ctf,
		}
		if !showCTflows {
			rule[i].CTFlows = nil
		}
	}
	return rule
}

func GetIPNet(ip string) *net.IPNet {
	if ip == "" {
		return nil
	}
	if !strings.Contains(ip, "/") {
		if utils.IsIPv4(ip) {
			ip += "/32"
		} else {
			ip += "/128"
		}
	}

	_, ipnet, _ := net.ParseCIDR(ip)
	return ipnet
}
