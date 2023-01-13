package datapath

import (
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/ofnet/ofctrl"
)

type BaseBridge struct {
	name     string
	OfSwitch *ofctrl.OFSwitch
	//nolint: structcheck
	datapathManager *DpManager

	isSwitchConnected bool
	switchStatusMutex sync.RWMutex
}

func (b *BaseBridge) GetName() string {
	return b.name
}

func (b *BaseBridge) SwitchConnected(sw *ofctrl.OFSwitch) {
	log.Infof("Switch %s connected", b.name)

	b.OfSwitch = sw

	b.switchStatusMutex.Lock()
	b.isSwitchConnected = true
	b.switchStatusMutex.Unlock()
}

func (b *BaseBridge) SwitchDisconnected(sw *ofctrl.OFSwitch) {
	log.Infof("Switch %s disconnected", b.name)

	b.switchStatusMutex.Lock()
	b.isSwitchConnected = false
	b.switchStatusMutex.Unlock()

	b.OfSwitch = nil
}

func (b *BaseBridge) IsSwitchConnected() bool {
	b.switchStatusMutex.Lock()
	defer b.switchStatusMutex.Unlock()

	return b.isSwitchConnected
}

func (b *BaseBridge) WaitForSwitchConnection() {
	for i := 0; i < 20; i++ {
		time.Sleep(1 * time.Second)
		b.switchStatusMutex.Lock()
		if b.isSwitchConnected {
			b.switchStatusMutex.Unlock()
			return
		}
		b.switchStatusMutex.Unlock()
	}

	log.Fatalf("OVS switch %s Failed to connect", b.name)
}

func (n *NatBridge) AddVNFInstance() error {
	return nil
}

func (n *NatBridge) RemoveVNFInstance() error {
	return nil
}

func (n *NatBridge) AddSFCRule() error {
	return nil
}

func (n *NatBridge) RemoveSFCRule() error {
	return nil
}

func (n *NatBridge) AddMicroSegmentRule(rule *EveroutePolicyRule, direction uint8, tier uint8, mode string) (*FlowEntry, error) {
	return nil, nil
}

func (n *NatBridge) RemoveMicroSegmentRule(rule *EveroutePolicyRule) error {
	return nil
}

// Controller received a packet from the switch
func (n *NatBridge) PacketRcvd(sw *ofctrl.OFSwitch, pkt *ofctrl.PacketIn) {}

// Controller received a multi-part reply from the switch
func (n *NatBridge) MultipartReply(sw *ofctrl.OFSwitch, rep *openflow13.MultipartReply) {}

func (b *BaseBridge) getOfSwitch() *ofctrl.OFSwitch {
	return b.OfSwitch
}
