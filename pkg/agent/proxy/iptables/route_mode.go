package iptables

import (
	"strings"

	"github.com/coreos/go-iptables/iptables"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
)

type RouteIPtables struct {
	baseIPtables
	proxy proxyIPtables
}

func NewRouteIPtables(enableEverouteProxy bool, opt *Options) *RouteIPtables {
	if enableEverouteProxy {
		return &RouteIPtables{
			baseIPtables: baseIPtables{},
			proxy:        &everouteProxy{},
		}
	}

	if opt == nil || opt.LocalGwName == "" {
		klog.Fatal("New RouteMode iptables controller with kube-proxy missing param local gw nic name")
	}
	return &RouteIPtables{
		baseIPtables: baseIPtables{},
		proxy:        &kubeProxy{localGwName: opt.LocalGwName},
	}
}

func (r *RouteIPtables) Update(nodeList corev1.NodeList, thisNode corev1.Node) {
	ipt, err := iptables.New()
	if err != nil {
		klog.Errorf("init iptables error, err: %s", err)
		return
	}

	r.acceptForward(ipt)

	everouteOutputChainErr := r.createEverouteOutputChain(ipt)
	if everouteOutputChainErr == nil {
		r.addEverouteOutputToPostrouting(ipt)
		r.updateEverouteOutputChain(ipt, nodeList, thisNode)
	} else {
		klog.Error("Failed to check and add EVEROUTE-OUTPUT chain, doesn't update rules in EVEROUTE-OUTPUT chain")
	}

	r.proxy.prerouting(ipt)
	r.proxy.forward(ipt)
}

func (r *RouteIPtables) updateEverouteOutputChain(ipt *iptables.IPTables, nodeList corev1.NodeList, thisNode corev1.Node) {
	var err error
	newRules := make(map[string]struct{})
	// check and add MASQUERADE in EVEROUTE-OUTPUT"
	for _, podCIDR := range thisNode.Spec.PodCIDRs {
		ruleSpec := []string{"-s", podCIDR, "-j", "MASQUERADE"}
		newRules[strings.Join(ruleSpec, " ")] = struct{}{}
		err = ipt.AppendUnique("nat", "EVEROUTE-OUTPUT", ruleSpec...)
		if err != nil {
			klog.Errorf("Add MASQUERADE rule in nat EVEROUTE-OUTPUT error, rule: %s, err: %s", ruleSpec, err)
			continue
		}
	}

	// check and add ACCEPT in EVEROUTE-OUTPUT
	// ACCEPT is used to skip the traffic inside the cluster.
	for _, podCIDR := range thisNode.Spec.PodCIDRs {
		for _, nodeItem := range nodeList.Items {
			if nodeItem.Name == thisNode.Name {
				continue
			}
			for _, otherPodCIDR := range nodeItem.Spec.PodCIDRs {
				if podCIDR == otherPodCIDR {
					klog.Errorf("Node %s and Node %s has same podCIDR %s", thisNode.Name, nodeItem.Name, podCIDR)
					continue
				}
				ruleSpec := []string{"-s", podCIDR, "-d", otherPodCIDR, "-j", "ACCEPT"}
				newRules[strings.Join(ruleSpec, " ")] = struct{}{}
				if err = ipt.InsertUnique("nat", "EVEROUTE-OUTPUT", 1, ruleSpec...); err != nil {
					klog.Errorf("[ALERT] Add ACCEPT rule in nat EVEROUTE-OUTPUT error, rule: %s, err: %s", ruleSpec, err)
					continue
				}
			}
		}
	}

	expectRules := r.proxy.everouteOutput(ipt)
	for i := range expectRules {
		newRules[expectRules[i]] = struct{}{}
	}

	r.deleteUnexpectRuleInEverouteOutput(ipt, newRules)
}
