package datapath

import (
	"fmt"
	"net"
	"strings"
	"testing"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/contiv/ofnet/ofctrl"
	"github.com/contiv/ofnet/ofctrl/cookie"
	"github.com/contiv/ofnet/ovsdbDriver"
	"k8s.io/klog/v2"

	"github.com/everoute/everoute/pkg/constants"
	"github.com/everoute/everoute/pkg/utils"
)

const (
	setupUplink = `
		set -o errexit
		set -o nounset
		set -o xtrace

		br_name=%s-uplink
		ovs-vsctl add-br ${br_name}
		ovs-vsctl add-port ${br_name} gw0 -- set interface gw0 type=internal
		ovs-vsctl add-port ${br_name} tocls -- set interface tocls type=internal
		ovs-vsctl add-port ${br_name} tonat -- set interface tonat type=internal
		ovs-vsctl add-port ${br_name} tunnel -- set interface tunnel type=internal
	`

	delUplink = `
		set -o errexit
		set -o nounset
		set -o xtrace
		br_name=%s-uplink
		ovs-vsctl del-br ${br_name}
	`
)

var uplinkBr *UplinkBridgeOverlay
var uplinkDpMgr *DpManager

func setupUplinkBridge() error {
	if err := ExcuteCommand(setupUplink, "testuplink"); err != nil {
		delUplinkBridge()
		return err
	}
	datapathManager := new(DpManager)
	datapathManager.Config = &DpManagerConfig{EnableCNI: true, CNIConfig: &DpManagerCNIConfig{EncapMode: "geneve", EnableProxy: true, KubeProxyReplace: true, SvcInternalIP: net.ParseIP("169.254.0.254")}}
	br := newUplinkBridgeOverlay("testuplink", datapathManager)
	uplinkBr = br
	control := ofctrl.NewOFController(br, utils.GenerateControllerID(constants.EverouteComponentType), nil, br.GetName())
	driver := ovsdbDriver.NewOvsDriverForExistBridge(br.GetName())

	datapathManager.BridgeChainMap = make(map[string]map[string]Bridge)
	datapathManager.BridgeChainMap["testuplink"] = make(map[string]Bridge)
	datapathManager.BridgeChainMap["testuplink"][UPLINK_BRIDGE_KEYWORD] = br
	protocols := map[string][]string{
		"protocols": {
			openflowProtorolVersion10, openflowProtorolVersion11, openflowProtorolVersion12, openflowProtorolVersion13,
		},
	}
	if err := driver.UpdateBridge(protocols); err != nil {
		return fmt.Errorf("set bridge %s protocols failed: %s", br.GetName(), err)
	}

	toNatOfPort, err := driver.GetOfpPortNo("tonat")
	if err != nil {
		return err
	}
	toClsOfPort, err := driver.GetOfpPortNo("tocls")
	if err != nil {
		return err
	}
	gwOfPort, err := driver.GetOfpPortNo("gw0")
	if err != nil {
		return err
	}
	tunOfPort, err := driver.GetOfpPortNo("tunnel")
	if err != nil {
		return err
	}
	datapathManager.BridgeChainPortMap = make(map[string]map[string]uint32)
	datapathManager.BridgeChainPortMap["testuplink"] = make(map[string]uint32)
	datapathManager.BridgeChainPortMap["testuplink"][UplinkToNatSuffix] = toNatOfPort
	datapathManager.BridgeChainPortMap["testuplink"][UplinkToClsSuffix] = toClsOfPort
	datapathManager.ControllerMap = make(map[string]map[string]*ofctrl.Controller)
	datapathManager.ControllerMap["testuplink"] = make(map[string]*ofctrl.Controller)
	datapathManager.ControllerMap["testuplink"]["uplink"] = control

	_, clusterCidr, _ := net.ParseCIDR("10.96.0.0/22")
	_, clusterPodCidr, _ := net.ParseCIDR("172.16.0.0/16")
	podGwIP := net.ParseIP("172.16.0.1")
	gwmac, _ := net.ParseMAC("00:00:5e:00:53:01")
	datapathManager.Info = new(DpManagerInfo)
	datapathManager.Info.GatewayIP = net.ParseIP("172.16.0.1")
	datapathManager.Info.ClusterCIDR = (*cnitypes.IPNet)(clusterCidr)
	datapathManager.Info.ClusterPodCIDR = clusterPodCidr
	datapathManager.Info.ClusterPodGw = &podGwIP
	datapathManager.Info.GatewayIP = net.ParseIP("172.16.0.1")
	datapathManager.Info.GatewayMac = gwmac
	datapathManager.Info.GatewayMask = net.IPMask(net.ParseIP("255.255.255.0"))
	datapathManager.Info.GatewayOfPort = gwOfPort
	datapathManager.Info.TunnelOfPort = tunOfPort
	uplinkDpMgr = datapathManager

	go control.Connect(fmt.Sprintf("%s/%s.%s", ovsVswitchdUnixDomainSockPath, br.GetName(), ovsVswitchdUnixDomainSockSuffix))

	if !datapathManager.IsBridgesConnected() {
		datapathManager.WaitForBridgeConnected()
	}

	roundInfo, err := getRoundInfo(driver)
	if err != nil {
		return err
	}
	cookieAllocator := cookie.NewAllocator(roundInfo.curRoundNum)
	br.getOfSwitch().CookieAllocator = cookieAllocator
	return nil
}

func delUplinkBridge() error {
	return ExcuteCommand(delUplink, "testuplink")
}

func TestBridgeInitCNI(t *testing.T) {
	t.Cleanup(func() {
		delUplinkBridge()
	})
	tests := []struct {
		name string
		ipam string
	}{
		{
			name: "use host local ipam for kube-proxy replace feature",
			ipam: "",
		},
		{
			name: "use host everoute ipam for kube-proxy replace feature",
			ipam: "everoute",
		},
	}

	for i := range tests {
		if err := setupUplinkBridge(); err != nil {
			t.Errorf("setup uplink bridge failed: %s", err)
		}
		uplinkDpMgr.Config.CNIConfig.IPAMType = tests[i].ipam
		uplinkBr.BridgeInitCNI()
		allFlows, err := dumpAllFlows(uplinkBr.GetName())
		if err != nil {
			t.Errorf("test %s failed for dump flows err: %s", tests[i].name, err)
		}
		res := checkUplinkFlow(allFlows, tests[i].ipam == "everoute")
		if !res {
			t.Errorf("test %s failed for not match flow, allflows: %v", tests[i].name, allFlows)
		}
		uplinkDpMgr.ControllerMap["testuplink"]["uplink"].Delete()
		delUplinkBridge()
	}
}

func validFlow(allFlows []string, tableID uint8, matchStr string) bool {
	for _, f := range allFlows {
		if !strings.Contains(f, fmt.Sprintf("table=%d", tableID)) {
			continue
		}
		if strings.Contains(f, matchStr) {
			return true
		}
	}

	klog.Errorf("no flow in table %d match %s", tableID, matchStr)
	return false
}

func checkUplinkFlow(allFlows []string, enableErIPam bool) bool {
	gwOfPort := uplinkDpMgr.Info.GatewayOfPort
	toNatOfPort := uplinkDpMgr.BridgeChainPortMap["testuplink"][UplinkToNatSuffix]
	if !validFlow(allFlows, 0, "priority=100,ip actions=resubmit(,15)") {
		return false
	}
	if !validFlow(allFlows, UBOArpProxyTable, fmt.Sprintf("priority=100,arp,in_port=%d,arp_op=1 actions=move:NXM_OF_ARP_TPA[]->NXM_OF_ARP_SPA[],move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],load:0xeeeeeeeeeeee->NXM_NX_ARP_SHA[],load:0x2->NXM_OF_ARP_OP[],move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],set_field:ee:ee:ee:ee:ee:ee->eth_src,IN_PORT", gwOfPort)) {
		return false
	}
	if !validFlow(allFlows, UBOSvcForwardTable, fmt.Sprintf("priority=300,pkt_mark=0x10000000/0x10000000,in_port=%d actions=resubmit(,24)", toNatOfPort)) {
		return false
	}
	if !validFlow(allFlows, UBOSvcForwardTable, fmt.Sprintf("priority=200,in_port=%d actions=resubmit(,30)", toNatOfPort)) {
		return false
	}
	if !validFlow(allFlows, UBOSvcForwardTable, "priority=10,ip actions=ct(table=20,zone=65503)") {
		return false
	}
	if !validFlow(allFlows, UBOSvcMatchTable, fmt.Sprintf("priority=300,ct_state=-new+trk,ip actions=load:%#x->NXM_NX_REG2[0..15],ct(commit,table=110,zone=65503,nat)", toNatOfPort)) {
		return false
	}
	if !validFlow(allFlows, UBOSvcMatchTable, fmt.Sprintf("priority=200,ip,in_port=%d,nw_dst=10.96.0.0/22 actions=resubmit(,90)", gwOfPort)) {
		return false
	}
	if !validFlow(allFlows, UBOSvcMatchTable, fmt.Sprintf("priority=200,pkt_mark=0x10000000/0x10000000,in_port=%d actions=resubmit(,90)", gwOfPort)) {
		return false
	}
	if !validFlow(allFlows, UBOSvcMatchTable, "priority=10 actions=resubmit(,30)") {
		return false
	}
	if !validFlow(allFlows, UBOResetSvcMarkTable, "priority=10 actions=load:0->NXM_NX_PKT_MARK[28],resubmit(,25)") {
		return false
	}
	if !validFlow(allFlows, UBOSvcSnatTable, "priority=300,pkt_mark=0x40000000/0x40000000,ip actions=load:0->NXM_NX_PKT_MARK[30],ct(commit,table=30,zone=65503)") {
		return false
	}
	if !validFlow(allFlows, UBOSvcSnatTable, "priority=200,ip,nw_dst=172.16.0.0/16 actions=ct(commit,table=30,zone=65503,nat(src=172.16.0.1))") {
		if !enableErIPam {
			return false
		}
	} else {
		if enableErIPam {
			klog.Error("can't set match podclustercidr flow")
			return false
		}
	}
	if !validFlow(allFlows, UBOSvcSnatTable, "ip actions=ct(commit,table=30,zone=65503,nat(src=169.254.0.254))") {
		return false
	}
	if !validFlow(allFlows, UBOSetSvcMarkTable, fmt.Sprintf("priority=300 actions=load:%#x->NXM_NX_REG2[0..15],load:0x1->NXM_NX_PKT_MARK[28],resubmit(,110)", toNatOfPort)) {
		return false
	}
	return true
}
