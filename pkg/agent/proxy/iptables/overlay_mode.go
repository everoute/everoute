package iptables

import (
	"strings"
	"sync"

	"github.com/coreos/go-iptables/iptables"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
)

type OverlayIPtables interface {
	Update()
	AddRuleByCIDR(cidr string) error
	DelRuleByCIDR(cidr string) error
	InsertPodCIDRs(cidrs ...string)
	DelPodCIDRs(cidrs ...string)
}

type overlayIPtables struct {
	baseIPtables
	proxy proxyIPtables

	lock     sync.RWMutex
	podCIDRs sets.Set[string]
}

func NewOverlayIPtables(enableEverouteProxy bool, opt *Options) OverlayIPtables {
	if opt == nil {
		klog.Fatal("New overlay mode iptables controller failed, param opt can't be nil")
	}

	o := &overlayIPtables{
		baseIPtables: baseIPtables{},
		podCIDRs:     sets.New[string](),
	}

	if enableEverouteProxy {
		o.proxy = &everouteProxy{
			kubeProxyReplace: opt.KubeProxyReplace,
			svcInternalIP:    opt.SvcInternalIP,
		}
	} else {
		if opt.LocalGwName == "" {
			klog.Fatal("New overlay mode iptables controller with kube-proxy failed, missing param local gw nic name")
		}
		o.proxy = &kubeProxy{localGwName: opt.LocalGwName}
	}

	if opt.ClusterPodCIDR != "" {
		o.podCIDRs.Insert(opt.ClusterPodCIDR)
	}
	return o
}

func (o *overlayIPtables) Update() {
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

func (o *overlayIPtables) updateEverouteOutputChain(ipt *iptables.IPTables) {
	o.lock.RLock()
	defer o.lock.RUnlock()

	newRules := make(map[string]struct{})

	cidrs := o.podCIDRs.UnsortedList()
	for _, c := range cidrs {
		ruleSpec := []string{"-s", c, "-j", "MASQUERADE"}
		newRules[strings.Join(ruleSpec, " ")] = struct{}{}
		err := ipt.AppendUnique("nat", "EVEROUTE-OUTPUT", ruleSpec...)
		if err != nil {
			klog.Errorf("Add MASQUERADE rule in nat EVEROUTE-OUTPUT error, rule: %s, err: %s", ruleSpec, err)
		}
	}

	expectRules := o.proxy.everouteOutput(ipt)
	for i := range expectRules {
		newRules[expectRules[i]] = struct{}{}
	}

	o.deleteUnexpectRuleInEverouteOutput(ipt, newRules)
}

func (o *overlayIPtables) AddRuleByCIDR(cidr string) error {
	ipt, err := iptables.New()
	if err != nil {
		klog.Errorf("init iptables error, err: %s", err)
		return err
	}

	ruleSpec := []string{"-s", cidr, "-j", "MASQUERADE"}
	err = ipt.AppendUnique("nat", "EVEROUTE-OUTPUT", ruleSpec...)
	if err != nil {
		klog.Errorf("Add MASQUERADE rule in nat EVEROUTE-OUTPUT error, rule: %s, err: %s", ruleSpec, err)
		return err
	}
	return nil
}

func (o *overlayIPtables) DelRuleByCIDR(cidr string) error {
	ipt, err := iptables.New()
	if err != nil {
		klog.Errorf("init iptables error, err: %s", err)
		return err
	}

	ruleSpec := []string{"-s", cidr, "-j", "MASQUERADE"}
	err = ipt.DeleteIfExists("nat", "EVEROUTE-OUTPUT", ruleSpec...)
	if err != nil {
		klog.Errorf("Delete MASQUERADE rule in nat EVEROUTE-OUTPUT error, rule: %s, err: %s", ruleSpec, err)
		return err
	}
	return nil
}

func (o *overlayIPtables) InsertPodCIDRs(cidrs ...string) {
	o.lock.Lock()
	defer o.lock.Unlock()

	o.podCIDRs.Insert(cidrs...)
}

func (o *overlayIPtables) DelPodCIDRs(cidrs ...string) {
	o.lock.Lock()
	defer o.lock.Unlock()

	o.podCIDRs.Delete(cidrs...)
}
