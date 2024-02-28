package iptables

import (
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"k8s.io/klog"
)

type Options struct {
	LocalGwName      string
	ClusterPodCIDR   string
	KubeProxyReplace bool
	SvcInternalIP    string
}

type baseIPtables struct{}

func (*baseIPtables) acceptForward(ipt *iptables.IPTables) {
	// set FORWARD in filter to accept
	err := ipt.ChangePolicy("filter", "FORWARD", "ACCEPT")
	if err != nil {
		klog.Errorf("Set iptables FORWARD error, error: %v", err)
	}
}

func (*baseIPtables) createEverouteOutputChain(ipt *iptables.IPTables) error {
	var err error
	var exist bool
	// check existence of chain EVEROUTE-OUTPUT, if not, then create it
	if exist, err = ipt.ChainExists("nat", "EVEROUTE-OUTPUT"); err != nil {
		klog.Errorf("Get iptables EVEROUTE-OUTPUT error, error: %s", err)
		return err
	}
	if !exist {
		err = ipt.NewChain("nat", "EVEROUTE-OUTPUT")
		if err != nil {
			klog.Errorf("Create iptables EVEROUTE-OUTPUT error, error: %s", err)
			return err
		}
	}
	return nil
}

func (*baseIPtables) addEverouteOutputToPostrouting(ipt *iptables.IPTables) {
	var err error
	// check and add EVEROUTE-OUTPUT to POSTROUTING
	if err = ipt.AppendUnique("nat", "POSTROUTING", "-j", "EVEROUTE-OUTPUT"); err != nil {
		klog.Errorf("Append EVEROUTE-OUTPUT into nat POSTROUTING error, err: %s", err)
	}
}

func (*baseIPtables) deleteUnexpectRuleInEverouteOutput(ipt *iptables.IPTables, expectRules map[string]struct{}) {
	oldRules, err := ipt.List("nat", "EVEROUTE-OUTPUT")
	if err != nil {
		klog.Errorf("Failed to get iptables chain EVEROUTE-OUTPUT rules, err: %v", err)
		return
	}
	for _, item := range oldRules {
		rule := strings.Split(item, " ")
		if len(rule) <= 2 {
			continue
		}
		ruleSpec := rule[2:]
		if _, ok := expectRules[strings.Join(ruleSpec, " ")]; !ok {
			if err = ipt.DeleteIfExists("nat", "EVEROUTE-OUTPUT", ruleSpec...); err != nil {
				klog.Errorf("Failed to delete unexpect iptables rule: %v, err: %v", ruleSpec, err)
				continue
			}
		}
	}
}
