package action

import (
	"fmt"
	"os/exec"
	"strings"

	"k8s.io/klog/v2"

	"github.com/everoute/everoute/pkg/constants/tr"
	"github.com/everoute/everoute/pkg/types"
)

func executeCommand(commandStr string) (string, error) {
	out, err := exec.Command("/bin/sh", "-c", commandStr).CombinedOutput()
	if err != nil {
		klog.Errorf("Failed to excute cmd: %s, out: %s, error: %v", commandStr, string(out), err)
		return "", fmt.Errorf("failed to excute cmd: %s, out: %s, error: %v", commandStr, string(out), err)
	}

	res := strings.TrimSpace(string(out))
	return res, nil
}

func getIfaceID(nic string) (string, error) {
	cmd := fmt.Sprintf("ovs-vsctl --if-exists get interface %s external_ids:iface-id", nic)
	res, err := executeCommand(cmd)
	if err != nil {
		klog.Errorf("Failed to get interface %s external_ids: %s", nic, err)
		return "", err
	}
	out := strings.Trim(strings.ReplaceAll(res, "\n", ""), `"`)
	return out, nil
}

func getPolicyBridgeName(ovsbrName string) string {
	return fmt.Sprintf("%s-policy", ovsbrName)
}

type Port struct {
	uuid   string
	name   string
	brName string

	intfIfaceID     string
	intfExternalIDs string
}

func (p *Port) checkTRNicInSvcChain(ifaceID string) bool {
	if p.brName != tr.SvcChainBridgeName {
		klog.Infof("Port %s mount bridge is %s, not svcchain bridge %s", p.name, p.brName, tr.SvcChainBridgeName)
		return false
	}
	if p.intfIfaceID != ifaceID {
		klog.Infof("Interface %s iface id is %s, not %s", p.name, p.intfIfaceID, ifaceID)
		return false
	}
	return true
}

func (p *Port) checkTRNicHasMount(ifaceID, ovsbrName string) bool {
	pBrName := getPolicyBridgeName(ovsbrName)
	if p.brName != pBrName {
		klog.Infof("Port %s mount bridge is %s, not ovs bridge %s", p.name, p.brName, pBrName)
		return false
	}
	if p.intfIfaceID != ifaceID {
		klog.Infof("Interface %s iface id is %s, not %s", p.name, p.intfIfaceID, ifaceID)
		return false
	}
	return true
}

func (p *Port) toNicCfg() *TRNicCfg {
	n := &TRNicCfg{
		IfaceID:  p.intfIfaceID,
		PortName: p.name,
	}
	if p.uuid != "" {
		n.PortUUID = p.uuid
	}
	return n
}

func getPortInfo(idOrName string) (*Port, error) {
	cmd := fmt.Sprintf("ovs-vsctl --if-exists get port %s _uuid name interfaces", idOrName)
	res, err := executeCommand(cmd)
	if err != nil {
		klog.Errorf("Failed to get ovs port %s: %s", idOrName, err)
		return nil, err
	}
	if res == "" {
		klog.Infof("Ovs port %s is not exist", idOrName)
		return nil, nil
	}
	resStr := strings.Split(res, "\n")
	if len(resStr) != 3 {
		klog.Errorf("Invalid port info: %s", res)
		return nil, fmt.Errorf("invalid port info")
	}
	p := &Port{uuid: resStr[0], name: resStr[1]}
	intfsStr := strings.Trim(resStr[2], "[]")
	intfs := strings.Split(intfsStr, ",")
	if len(intfs) != 1 {
		klog.Errorf("Invalid interfaces %s", resStr[1])
		return nil, fmt.Errorf("invalid port info")
	}
	intfID := intfs[0]
	intfE, err := getInterfaceExternalIDs(intfID)
	if err != nil {
		return nil, err
	}
	p.intfExternalIDs = intfE

	p.intfIfaceID, err = getIfaceID(intfID)
	if err != nil {
		return nil, err
	}
	if p.intfIfaceID == "" {
		klog.Errorf("can't find interface %s ifaceID", intfID)
		return nil, fmt.Errorf("can't find interface %s ifaceID", intfID)
	}

	cmd = fmt.Sprintf("ovs-vsctl port-to-br %s", p.name)
	res, err = executeCommand(cmd)
	if err != nil {
		klog.Errorf("Failed to get port %s mount bridge: %s", p.name, err)
		return nil, err
	}
	p.brName = res
	if p.brName == "" {
		klog.Errorf("port %s mount to empty bridge", p.name)
		return nil, fmt.Errorf("port %s mount to empty bridge", p.name)
	}
	return p, nil
}

func getInterfaceExternalIDs(id string) (string, error) {
	cmd := fmt.Sprintf("ovs-vsctl get interface %s external_ids", id)
	res, err := executeCommand(cmd)
	if err != nil {
		klog.Errorf("Failed to get interface %s external_ids: %s", id, err)
		return "", err
	}
	return strings.ReplaceAll(res, "\n", ""), nil
}

func UnmountTRNic(ovsbrName string, d types.NicDirect) error {
	nicCfg, err := getNicConfig(ovsbrName, d)
	if err != nil {
		return err
	}
	if nicCfg == nil {
		klog.Infof("Can't find trafficredirect nic config for ovs bridge %s direct %s , return", ovsbrName, d)
		return nil
	}

	cfgP := nicCfg.PortName
	if nicCfg.PortUUID != "" {
		cfgP = nicCfg.PortUUID
	}
	p, err := getPortInfo(cfgP)
	if err != nil {
		return err
	}
	if p == nil {
		klog.Infof("Port %s is not exist", cfgP)
		if err := delNicConfig(ovsbrName, d); err != nil {
			return fmt.Errorf("failed to del ovs bridge %s trafficredirect nic for direct %s config: %s", ovsbrName, d, err)
		}
		klog.Infof("Success clean svcchain externalid %s for port %s doesn't exist", getExternalIDKey(ovsbrName, d), nicCfg.PortName)
		return nil
	}

	policyBrName := getPolicyBridgeName(ovsbrName)
	if !p.checkTRNicHasMount(nicCfg.IfaceID, ovsbrName) {
		klog.Errorf("Port %s is not trafficredirect nic for ovs bridge %s direct %s", p.name, ovsbrName, d)
		return fmt.Errorf("invalid trafficdirect nic")
	}

	cmd := fmt.Sprintf("ovs-vsctl del-port %s %s -- add-port %s %s -- set interface %s external_ids='%s' -- br-set-external-id %s %s",
		policyBrName, p.name, tr.SvcChainBridgeName, p.name, p.name, p.intfExternalIDs, tr.SvcChainBridgeName, getExternalIDKey(ovsbrName, d))
	if _, err := executeCommand(cmd); err != nil {
		klog.Errorf("Failed to unmount trafficredirect nic %v from ovs bridge %s", *p, ovsbrName)
		return err
	}
	klog.Infof("Success to unmount trafficredirect nic %v from ovs bridge %s", *p, ovsbrName)
	return nil
}

func MustMountTRNic(ovsbrName, ifaceName, ifaceID string, d types.NicDirect) {
	for i := 0; i < tr.DpActionMaxRetryTimes; i++ {
		if err := MountTRNic(ovsbrName, ifaceName, ifaceID, d); err != nil {
			klog.Errorf("Try %d times, failed to mount tr nic %s with ifaceID %s to policy bridge %s-policy: %s", i, ifaceName, ifaceID, ovsbrName, err)
			continue
		}
		klog.Infof("Try %d times, success to mount tr nic %s with ifaceID %s to policy bridge %s-policy", i, ifaceName, ifaceID, ovsbrName)
		return
	}
	klog.Fatalf("Failed to mount tr nic %s to policy brige %s-policy after %d times", ifaceName, ovsbrName, tr.DpActionMaxRetryTimes)
}

func MountTRNic(ovsbrName, ifaceName, ifaceID string, d types.NicDirect) error {
	p, err := getPortInfo(ifaceName)
	if err != nil {
		return err
	}
	if p == nil {
		return fmt.Errorf("port doesn't %s exist", ifaceName)
	}
	if p.intfIfaceID != ifaceID {
		klog.Errorf("Port %v is not match ifaceID %s", *p, ifaceID)
		return fmt.Errorf("port has changed ifaceID")
	}

	if !p.checkTRNicHasMount(ifaceID, ovsbrName) && !p.checkTRNicInSvcChain(ifaceID) {
		klog.Errorf("Port %v is not mount ovs bridge %s and not mount svcchain bridge", *p, ovsbrName)
		return fmt.Errorf("invalid trafficredirect port")
	}
	nicCfg, err := getNicConfig(ovsbrName, d)
	if err != nil {
		return err
	}
	if nicCfg == nil {
		return mountTRNicWithPort(ovsbrName, d, p)
	}
	// niccfg != nil
	if nicCfg.IfaceID != p.intfIfaceID {
		klog.Errorf("Please unmount nic %s (uuid: %s) with iface-id %s first", nicCfg.PortName, nicCfg.PortUUID, nicCfg.IfaceID)
		return fmt.Errorf("ovs bridge has mount trafficredirect nic with different iface-id")
	}

	if nicCfg.PortUUID != "" {
		oldP, err := getPortInfo(nicCfg.PortUUID)
		if err != nil {
			return err
		}
		if oldP == nil {
			return mountTRNicWithPort(ovsbrName, d, p)
		}
		if oldP.uuid == p.uuid {
			return mountTRNicWithPort(ovsbrName, d, p)
		}
		klog.Errorf("Old port %v doesn't match config %v", *oldP, *nicCfg)
		return fmt.Errorf("old port doesn't match config")
	}

	oldP, err := getPortInfo(nicCfg.PortName)
	if err != nil {
		return err
	}
	if oldP == nil {
		return mountTRNicWithPort(ovsbrName, d, p)
	}
	if oldP.intfIfaceID != nicCfg.IfaceID {
		klog.Infof("Port name %s has reused, it is not trafficredirect nic, need to mount trafficredirect again", oldP.name)
		return mountTRNicWithPort(ovsbrName, d, p)
	}
	if oldP.name == p.name {
		return mountTRNicWithPort(ovsbrName, d, p)
	}
	klog.Errorf("Port %v and port %v all match ifaceID %s, it's unexpect, please process by manual", *p, *oldP, ifaceID)
	return fmt.Errorf("multi ports match ifaceID")
}

func mountTRNicWithPort(ovsbrName string, d types.NicDirect, p *Port) error {
	if p == nil {
		return fmt.Errorf("param port is nil")
	}
	if p.checkTRNicHasMount(p.intfIfaceID, ovsbrName) {
		cfg := p.toNicCfg()
		if err := updateNicConfig(ovsbrName, d, cfg); err != nil {
			klog.Errorf("Failed to update port %v trafficredirect nic config for ovs bridge %s direct %s: %s", *p, ovsbrName, d, err)
			return err
		}
		klog.Infof("Success to update port %v trafficredirect nic config for ovs bridge %s direct %s", *p, ovsbrName, d)
		return nil
	}

	oldPortUUID := p.uuid
	// clear port uuid before mount to policy bridge
	p.uuid = ""
	newCfg := p.toNicCfg()
	external, err := newCfg.toBase64()
	if err != nil {
		return err
	}
	policyBrName := getPolicyBridgeName(ovsbrName)
	cmd := fmt.Sprintf("ovs-vsctl del-port %s %s -- add-port %s %s -- set interface %s external_ids='%s' -- br-set-external-id %s %s %s",
		tr.SvcChainBridgeName, p.name, policyBrName, p.name, p.name, p.intfExternalIDs, tr.SvcChainBridgeName,
		getExternalIDKey(ovsbrName, d), external)
	if _, err := executeCommand(cmd); err != nil {
		klog.Errorf("Failed to mount trafficredirect nic %v with port uuid %s to ovs bridge %s", *p, oldPortUUID, ovsbrName)
		return err
	}
	klog.Infof("Success to mount trafficredirect nic %v to ovs bridge %s", *p, ovsbrName)

	// add port uuid to nic config in svcchian bridge externalids
	newP, err := getPortInfo(p.name)
	if err != nil {
		klog.Errorf("Failed to get new port after mount: %s", err)
		return err
	}
	if !newP.checkTRNicHasMount(p.intfIfaceID, ovsbrName) {
		klog.Errorf("Can't find mount port %s", p.name)
		return fmt.Errorf("can't find mount port to update config uuid")
	}
	newCfg = newP.toNicCfg()
	if err := updateNicConfig(ovsbrName, d, newCfg); err != nil {
		klog.Errorf("Failed to update port %v uuid to trafficredirect nic config in external_ids: %s", *newP, err)
		return err
	}
	klog.Infof("Success to update port %v uuid to trafficredirect nic config in external_ids", *newP)
	return nil
}

func findTrafficRedirectNic(ovsbrName, ifaceID string, d types.NicDirect) (string, error) {
	cmd := fmt.Sprintf("ovs-vsctl --columns=name find Interface external_ids:iface-id=%s", ifaceID)
	resS, err := executeCommand(cmd)
	if err != nil {
		return "", err
	}
	resStr := strings.TrimSuffix(resS, "\n")
	if resStr == "" {
		klog.Errorf("can't find interface with ifaceID %s for ovs bridge %s direct %s", ifaceID, ovsbrName, d)
		return "", ErrNicNotFound
	}
	res := strings.Split(resStr, "\n")
	if len(res) == 0 {
		klog.Errorf("can't find interface with ifaceID %s for ovs bridge %s direct %s", ifaceID, ovsbrName, d)
		return "", ErrNicNotFound
	}
	if len(res) > 1 {
		klog.Errorf("find multi interface with ifaceID %s for ovs bridge %s direct %s, res: %s", ifaceID, ovsbrName, d, resS)
		return "", fmt.Errorf("find multi nic match trafficredirect")
	}
	outs := strings.Split(res[0], ":")
	if len(outs) != 2 {
		klog.Errorf("invalid ovs out: %s", res[0])
		return "", fmt.Errorf("invalid ovs out")
	}
	return strings.TrimSpace(outs[1]), nil
}
