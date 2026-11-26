package datapath

import (
	"fmt"
	"strings"
	"testing"

	"github.com/contiv/ofnet/ofctrl"
	"github.com/contiv/ofnet/ofctrl/cookie"
	"github.com/contiv/ofnet/ovsdbDriver"

	"github.com/everoute/everoute/pkg/constants"
	"github.com/everoute/everoute/pkg/utils"
)

const (
	setupUplinkNocni = `
		set -o errexit
		set -o nounset
		set -o xtrace

		br_name=%s-uplink
		ovs-vsctl add-br ${br_name}
		ovs-vsctl add-port ${br_name} tocls -- set interface tocls type=internal
		ovs-vsctl add-port ${br_name} fromcls -- set interface fromcls type=internal
	`

	delUplinkNocni = `
		set -o errexit
		set -o nounset
		set -o xtrace

		br_name=%s-uplink
		ovs-vsctl del-br ${br_name}
	`
)

var uplinkNocniBr *UplinkBridge
var uplinkNocniDpMgr *DpManager

func setupUplinkNocniBridge() error {
	if err := ExcuteCommand(setupUplinkNocni, "testuplinknocni"); err != nil {
		delUplinkNocniBridge()
		return err
	}
	datapathManager := new(DpManager)
	datapathManager.Config = &DpManagerConfig{EnableCNI: false}
	br := newUplinkBridge("testuplinknocni", "testvds", datapathManager)
	uplinkNocniBr = br
	control := ofctrl.NewOFController(br, utils.GenerateControllerID(constants.EverouteComponentType), nil, br.GetName())
	driver := ovsdbDriver.NewOvsDriverForExistBridge(br.GetName())

	datapathManager.BridgeChainMap = make(map[string]map[string]Bridge)
	datapathManager.BridgeChainMap["testuplinknocni"] = make(map[string]Bridge)
	datapathManager.BridgeChainMap["testuplinknocni"][UPLINK_BRIDGE_KEYWORD] = br
	protocols := map[string][]string{
		"protocols": {
			openflowProtorolVersion10, openflowProtorolVersion11, openflowProtorolVersion12, openflowProtorolVersion13,
		},
	}
	if err := driver.UpdateBridge(protocols); err != nil {
		return fmt.Errorf("set bridge %s protocols failed: %s", br.GetName(), err)
	}

	toClsOfPort, err := driver.GetOfpPortNo("tocls")
	if err != nil {
		return err
	}
	fromClsOfPort, err := driver.GetOfpPortNo("fromcls")
	if err != nil {
		return err
	}
	datapathManager.BridgeChainPortMap = make(map[string]map[string]uint32)
	datapathManager.BridgeChainPortMap["testuplinknocni"] = make(map[string]uint32)
	datapathManager.BridgeChainPortMap["testuplinknocni"][UplinkToClsSuffix] = toClsOfPort
	datapathManager.BridgeChainPortMap["testuplinknocni"][ClsToUplinkSuffix] = fromClsOfPort
	datapathManager.ControllerMap = make(map[string]map[string]*ofctrl.Controller)
	datapathManager.ControllerMap["testuplinknocni"] = make(map[string]*ofctrl.Controller)
	datapathManager.ControllerMap["testuplinknocni"]["uplink"] = control
	uplinkNocniDpMgr = datapathManager

	go control.Connect(fmt.Sprintf("%s/%s.%s", ovsVswitchdUnixDomainSockPath, br.GetName(), ovsVswitchdUnixDomainSockSuffix))

	if !datapathManager.IsBridgesConnected() {
		datapathManager.WaitForBridgeConnected()
	}

	roundInfos, err := getDatapathRoundInfosAsPrevious(
		[]string{"testuplinknocni"},
		map[string]map[string]*ovsdbDriver.OvsDriver{
			"testuplinknocni": {
				LOCAL_BRIDGE_KEYWORD: driver,
			},
		},
	)
	if err != nil {
		return err
	}
	assignNewRoundInfos(roundInfos)
	roundInfo := roundInfos["testuplinknocni"]
	br.SetRoundInfo(roundInfo)
	cookieAllocator := cookie.NewAllocator(roundInfo.currentRoundNum)
	br.getOfSwitch().CookieAllocator = cookieAllocator
	return nil
}

func delUplinkNocniBridge() error {
	return ExcuteCommand(delUplinkNocni, "testuplinknocni")
}

func TestUplinkBridgeInit(t *testing.T) {
	t.Cleanup(func() {
		delUplinkNocniBridge()
	})

	if err := setupUplinkNocniBridge(); err != nil {
		t.Fatalf("setup uplink nocni bridge failed: %s", err)
	}

	uplinkNocniBr.BridgeInit()

	allFlows, err := dumpAllFlows(uplinkNocniBr.GetName())
	if err != nil {
		t.Fatalf("dump flows err: %s", err)
	}

	toClsOfPort := uplinkNocniDpMgr.BridgeChainPortMap["testuplinknocni"][UplinkToClsSuffix]
	fromClsOfPort := uplinkNocniDpMgr.BridgeChainPortMap["testuplinknocni"][ClsToUplinkSuffix]

	// East-west traffic entering from the cls bridge should match the uplink-to-cls
	// port and be exempted from the "source = uplink" marking.
	if !validFlow(allFlows, 0, fmt.Sprintf("priority=100,in_port=%d actions=NORMAL", toClsOfPort)) {
		t.Errorf("exempt flow should match uplink-to-cls port %d, allflows: %v", toClsOfPort, allFlows)
	}
	// It must not match the cls-to-uplink port, which lives on the cls bridge instead
	// of the uplink bridge.
	for _, f := range allFlows {
		if strings.Contains(f, fmt.Sprintf("priority=100,in_port=%d", fromClsOfPort)) {
			t.Errorf("exempt flow should not match cls-to-uplink port %d, allflows: %v", fromClsOfPort, allFlows)
		}
	}

	// The default flow should carry both the inport mark and the source-bridge mark
	// before normal lookup.
	if !validFlow(allFlows, 0, "priority=10 actions=move:NXM_OF_IN_PORT[]->NXM_NX_PKT_MARK[0..15],load:0x3->NXM_NX_PKT_MARK[17..18],NORMAL") {
		t.Errorf("default flow should mark packet source bridge and inport, allflows: %v", allFlows)
	}

	uplinkNocniBr.OfSwitch.Disconnect()
	uplinkNocniDpMgr.ControllerMap["testuplinknocni"]["uplink"].Delete()
}
