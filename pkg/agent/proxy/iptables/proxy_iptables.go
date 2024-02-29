package iptables

import (
	"fmt"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"k8s.io/klog"

	"github.com/everoute/everoute/pkg/constants"
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
		klog.Errorf("Insert %s into nat EVEROUTE-OUTPUT error, err: %s", k.localGwName, err)
	}
	return []string{expectRule}
}

func (k *kubeProxy) forward(ipt *iptables.IPTables) {
	var err error
	// allow ct invalid from gw-local
	if err = ipt.InsertUnique("filter", "FORWARD", 1, "-i", k.localGwName,
		"-m", "conntrack", "--ctstate", "INVALID", "-j", "ACCEPT"); err != nil {
		klog.Errorf("Insert filter FORWARD error, err: %s", err)
	}
}

func (k *kubeProxy) prerouting(ipt *iptables.IPTables) {
	var err error
	// check and add CT zone for gw-local
	ctZoneStr := fmt.Sprintf("%d", constants.CTZoneLocalBr)
	if err = ipt.InsertUnique("raw", "PREROUTING", 1, "-i", k.localGwName, "-j", "CT", "--zone", ctZoneStr); err != nil {
		klog.Errorf("Insert %s into raw PREROUTING error, err: %s", k.localGwName, err)
	}
}

type everouteProxy struct {
	kubeProxyReplace bool
	svcInternalIP    string
}

func (e *everouteProxy) everouteOutput(ipt *iptables.IPTables) []string {
	if !e.kubeProxyReplace {
		return nil
	}
	if e.svcInternalIP == "" {
		klog.Error("Doesn't set svcInternalIP when enable kubeProxyReplace")
		return nil
	}

	ruleSpec := []string{"-s", e.svcInternalIP + "/32", "-j", "MASQUERADE"}
	expectRule := strings.Join(ruleSpec, " ")
	if err := ipt.InsertUnique("nat", "EVEROUTE-OUTPUT", 1, ruleSpec...); err != nil {
		klog.Errorf("Insert svcInternalIP %s into nat EVEROUTE-OUTPUT error, err: %s", e.svcInternalIP, err)
	}
	return []string{expectRule}
}

func (*everouteProxy) forward(*iptables.IPTables) {}

func (e *everouteProxy) prerouting(ipt *iptables.IPTables) {
	if !e.kubeProxyReplace {
		return
	}

	var err error
	if err = e.createEverouteSvcChain(ipt); err != nil {
		return
	}
	e.addEverouteSvcToPrerouting(ipt)

	if err = ipt.AppendUnique("mangle", constants.SvcChain, getRuleSpecByIPSet(constants.IPSetNameNPSvcTCP)...); err != nil {
		klog.Errorf("Failed to add iptables rule to %s for nodeport svc with tcp, err: %s", constants.SvcChain, err)
	}
	if err = ipt.AppendUnique("mangle", constants.SvcChain, getRuleSpecByIPSet(constants.IPSetNameNPSvcUDP)...); err != nil {
		klog.Errorf("Failed to add iptables rule to %s for nodeport svc with udp, err: %s", constants.SvcChain, err)
	}
	if err = ipt.AppendUnique("mangle", constants.SvcChain, getRuleSpecByIPSet(constants.IPSetNameLBSvc)...); err != nil {
		klog.Errorf("Failed to add iptables rule to %s for loadbalancer svc, err: %s", constants.SvcChain, err)
	}
}

func (*everouteProxy) createEverouteSvcChain(ipt *iptables.IPTables) error {
	var err error
	var exist bool
	// check existence of chain EVEROUTE-SVC, if not, then create it
	if exist, err = ipt.ChainExists("mangle", constants.SvcChain); err != nil {
		klog.Errorf("Get iptables %s error, error: %s", constants.SvcChain, err)
		return err
	}
	if !exist {
		err = ipt.NewChain("mangle", constants.SvcChain)
		if err != nil {
			klog.Errorf("Create iptables %s error, error: %s", constants.SvcChain, err)
			return err
		}
	}
	return nil
}

func (*everouteProxy) addEverouteSvcToPrerouting(ipt *iptables.IPTables) {
	if err := ipt.InsertUnique("mangle", "PREROUTING", 1, "-j", constants.SvcChain); err != nil {
		klog.Errorf("insert %s into nat PREROUTING error, err: %s", constants.SvcChain, err)
	}
}

var _ proxyIPtables = &kubeProxy{localGwName: ""}
var _ proxyIPtables = &everouteProxy{kubeProxyReplace: false, svcInternalIP: ""}

func getRuleSpecByIPSet(set string) []string {
	rule := []string{}

	// protocol
	if set == constants.IPSetNameNPSvcTCP {
		rule = append(rule, "-p", "tcp")
	}
	if set == constants.IPSetNameNPSvcUDP {
		rule = append(rule, "-p", "udp")
	}

	// match set
	rule = append(rule, "-m", "set", "--match-set", set)
	if set == constants.IPSetNameLBSvc {
		rule = append(rule, "dst,dst")
	} else {
		rule = append(rule, "dst")
	}

	// mark
	svcPktMarkString := fmt.Sprintf("%#x/%#x", 1<<constants.ExternalSvcPktMarkBit, 1<<constants.ExternalSvcPktMarkBit)
	rule = append(rule, "-j", "MARK", "--set-xmark", svcPktMarkString)

	return rule
}
