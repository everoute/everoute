package iptables

import (
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"k8s.io/klog"
)

type OverlayIPtables struct {
	baseIPtables
	proxy proxyIPtables

	clusterPodCIDR string
}

func NewOverlayIPtables(enableEverouteProxy bool, opt *Options) *OverlayIPtables {
	if opt == nil || opt.ClusterPodCIDR == "" {
		klog.Fatal("New overlay mode iptables controller failed, missing param ClusterPodCIDR")
	}
	if enableEverouteProxy {
		return &OverlayIPtables{
			baseIPtables:   baseIPtables{},
			proxy:          &everouteProxy{},
			clusterPodCIDR: opt.ClusterPodCIDR,
		}
	}

	if opt.LocalGwName == "" {
		klog.Fatal("New overlay mode iptables controller with kube-proxy failed, missing param local gw nic name")
	}
	return &OverlayIPtables{
		baseIPtables:   baseIPtables{},
		proxy:          &kubeProxy{localGwName: opt.LocalGwName},
		clusterPodCIDR: opt.ClusterPodCIDR,
	}
}

func (o *OverlayIPtables) Update() {
	ipt, err := iptables.New()
	if err != nil {
		klog.Errorf("init iptables error, err: %s", err)
		return
	}

	o.acceptForward(ipt)

	everouteOutputChainErr := o.createEverouteOutputChain(ipt)
	if everouteOutputChainErr == nil {
		o.addEverouteOutputToPostrouting(ipt)
		o.updateEverouteOutputChain(ipt)
	} else {
		klog.Error("Failed to check and add EVEROUTE-OUTPUT chain, doesn't update rules in EVEROUTE-OUTPUT chain")
	}

	o.proxy.prerouting(ipt)
	o.proxy.forward(ipt)
}

func (o *OverlayIPtables) updateEverouteOutputChain(ipt *iptables.IPTables) {
	var err error
	newRules := make(map[string]struct{})

	ruleSpec := []string{"-s", o.clusterPodCIDR, "-j", "MASQUERADE"}
	newRules[strings.Join(ruleSpec, " ")] = struct{}{}
	err = ipt.AppendUnique("nat", "EVEROUTE-OUTPUT", ruleSpec...)
	if err != nil {
		klog.Errorf("Add MASQUERADE rule in nat EVEROUTE-OUTPUT error, rule: %s, err: %s", ruleSpec, err)
	}

	expectRules := o.proxy.everouteOutput(ipt)
	for i := range expectRules {
		newRules[expectRules[i]] = struct{}{}
	}

	o.deleteUnexpectRuleInEverouteOutput(ipt, newRules)
}
