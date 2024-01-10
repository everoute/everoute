package iptables

import (
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"k8s.io/klog"
)

type proxyIPtables interface {
	everouteOutput(ipt *iptables.IPTables) []string
	forward(ipt *iptables.IPTables)
	prerouting(ipt *iptables.IPTables)
}

type kubeProxy struct {
	localGwName string
}

func (k *kubeProxy) everouteOutput(ipt *iptables.IPTables) []string {
	var err error
	// check and add ACCEPT for traffic from gw-local
	ruleSpec := []string{"-o", k.localGwName, "-j", "ACCEPT"}
	expectRule := strings.Join(ruleSpec, " ")
	if err = ipt.InsertUnique("nat", "EVEROUTE-OUTPUT", 1, ruleSpec...); err != nil {
		klog.Errorf("Append %s into nat EVEROUTE-OUTPUT error, err: %s", k.localGwName, err)
	}
	return []string{expectRule}
}

func (k *kubeProxy) forward(ipt *iptables.IPTables) {
	var err error
	// allow ct invalid from gw-local
	if err = ipt.InsertUnique("filter", "FORWARD", 1, "-i", k.localGwName,
		"-m", "conntrack", "--ctstate", "INVALID", "-j", "ACCEPT"); err != nil {
		klog.Errorf("Append filter FORWARD error, err: %s", err)
	}
}

func (k *kubeProxy) prerouting(ipt *iptables.IPTables) {
	var err error
	// check and add CT zone for gw-local
	if err = ipt.InsertUnique("raw", "PREROUTING", 1, "-i", k.localGwName, "-j", "CT", "--zone", "65510"); err != nil {
		klog.Errorf("Append %s into raw PREROUTING error, err: %s", k.localGwName, err)
	}
}

type everouteProxy struct{}

func (*everouteProxy) everouteOutput(*iptables.IPTables) []string { return []string{} }

func (*everouteProxy) forward(*iptables.IPTables) {}

func (*everouteProxy) prerouting(*iptables.IPTables) {}

var _ proxyIPtables = &kubeProxy{localGwName: ""}
var _ proxyIPtables = &everouteProxy{}
