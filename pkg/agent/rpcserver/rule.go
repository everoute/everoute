package rpcserver

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/everoute/everoute/pkg/agent/datapath"
	getter "github.com/everoute/everoute/pkg/apis/rule/v1alpha1"
)

type Getter struct {
	dpManager *datapath.DpManager
}

func (g *Getter) GetAllRules(context.Context, *emptypb.Empty) (*getter.RuleEntries, error) {
	rules := g.dpManager.GetAllRules()
	return &getter.RuleEntries{RuleEntries: rules}, nil
}

func (g *Getter) GetRulesByName(ctx context.Context, ruleIDs *getter.RuleIDs) (*getter.RuleEntries, error) {
	rules := g.dpManager.GetRulesByRuleIDs(ruleIDs.RuleIDs...)
	return &getter.RuleEntries{RuleEntries: rules}, nil
}

func (g *Getter) GetRulesByFlow(ctx context.Context, flowIDs *getter.FlowIDs) (*getter.RuleEntries, error) {
	rules := g.dpManager.GetRulesByFlowIDs(flowIDs.FlowIDs...)
	return &getter.RuleEntries{RuleEntries: rules}, nil
}

func NewGetterServer(datapathManager *datapath.DpManager) *Getter {
	s := &Getter{
		dpManager: datapathManager,
	}

	return s
}
