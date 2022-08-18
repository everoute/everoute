package rpcserver

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/everoute/everoute/pkg/agent/datapath"
	"github.com/everoute/everoute/pkg/apis/rpc/v1alpha1"
)

type Getter struct {
	dpManager *datapath.DpManager
}

func (g *Getter) GetAllRules(context.Context, *emptypb.Empty) (*v1alpha1.RuleEntries, error) {
	rules := g.dpManager.GetAllRules()
	return &v1alpha1.RuleEntries{RuleEntries: rules}, nil
}

func (g *Getter) GetRulesByName(ctx context.Context, ruleIDs *v1alpha1.RuleIDs) (*v1alpha1.RuleEntries, error) {
	rules := g.dpManager.GetRulesByRuleIDs(ruleIDs.RuleIDs...)
	return &v1alpha1.RuleEntries{RuleEntries: rules}, nil
}

func (g *Getter) GetRulesByFlow(ctx context.Context, flowIDs *v1alpha1.FlowIDs) (*v1alpha1.RuleEntries, error) {
	rules := g.dpManager.GetRulesByFlowIDs(flowIDs.FlowIDs...)
	return &v1alpha1.RuleEntries{RuleEntries: rules}, nil
}

func NewGetterServer(datapathManager *datapath.DpManager) *Getter {
	s := &Getter{
		dpManager: datapathManager,
	}

	return s
}
