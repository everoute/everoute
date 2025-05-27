package datapath

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/ofnet/ofctrl"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type BaseBridge struct {
	name      string
	index     uint32
	ovsBrName string
	OfSwitch  *ofctrl.OFSwitch
	//nolint: structcheck
	datapathManager *DpManager

	isSwitchConnected bool

	switchStatusMutex   sync.RWMutex
	disconnectChan      chan struct{}
	disconnectChanMutex sync.Mutex

	roundNum uint64
}

var _ Bridge = &BaseBridge{}

func (b *BaseBridge) getDisconnectChan() chan struct{} {
	b.disconnectChanMutex.Lock()
	defer b.disconnectChanMutex.Unlock()
	if b.disconnectChan == nil {
		b.disconnectChan = make(chan struct{}, 1)
	}
	return b.disconnectChan
}

func (b *BaseBridge) GetName() string {
	return b.name
}

func (b *BaseBridge) GetIndex() (uint32, error) {
	index := atomic.LoadUint32(&b.index)
	if index == 0 {
		link, err := netlink.LinkByName(b.GetName())
		if err != nil {
			return 0, err
		}
		index = uint32(link.Attrs().Index)
		atomic.StoreUint32(&b.index, index)
	}
	return index, nil
}

func (b *BaseBridge) SetRoundNumber(n uint64) {
	b.roundNum = n
}

func (b *BaseBridge) SwitchConnected(sw *ofctrl.OFSwitch) {
	b.switchStatusMutex.Lock()
	log.Infof("Switch %s connected", b.name)
	b.OfSwitch = sw
	b.isSwitchConnected = true
	b.switchStatusMutex.Unlock()
}

func (b *BaseBridge) SwitchDisconnected(_ *ofctrl.OFSwitch) {
	b.switchStatusMutex.Lock()
	log.Infof("Switch %s disconnected", b.name)
	b.isSwitchConnected = false
	select {
	case b.getDisconnectChan() <- struct{}{}:
	default:
	}
	b.switchStatusMutex.Unlock()
}

func (b *BaseBridge) DisconnectedNotify() chan struct{} {
	return b.getDisconnectChan()
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

func (b *BaseBridge) BridgeInit() {}

func (b *BaseBridge) BridgeInitCNI() {}

func (b *BaseBridge) AddVNFInstance() error {
	return nil
}

func (b *BaseBridge) RemoveVNFInstance() error {
	return nil
}

func (b *BaseBridge) AddSFCRule() error {
	return nil
}

func (b *BaseBridge) RemoveSFCRule() error {
	return nil
}

func (b *BaseBridge) AddMicroSegmentRule(context.Context, uint32, *EveroutePolicyRule, uint8, uint8, string) (*FlowEntry, error) {
	return nil, nil
}

// Controller received a packet from the switch
func (b *BaseBridge) PacketRcvd(*ofctrl.OFSwitch, *ofctrl.PacketIn) {}

// Controller received a multi-part reply from the switch
func (b *BaseBridge) MultipartReply(*ofctrl.OFSwitch, *openflow13.MultipartReply) {}

func (b *BaseBridge) getOfSwitch() *ofctrl.OFSwitch {
	return b.OfSwitch
}

func (b *BaseBridge) AddLocalEndpoint(*Endpoint) error {
	return nil
}

func (b *BaseBridge) RemoveLocalEndpoint(*Endpoint) error {
	return nil
}

func (b *BaseBridge) BridgeReset() {}

func (b *BaseBridge) AddIPPoolSubnet(string) error {
	return nil
}

func (b *BaseBridge) DelIPPoolSubnet(string) error {
	return nil
}

func (b *BaseBridge) AddIPPoolGW(string) error {
	return nil
}

func (b *BaseBridge) DelIPPoolGW(string) error {
	return nil
}

func (b *BaseBridge) UpdateTREndpoint(*Endpoint) error {
	return nil
}

func (b *BaseBridge) DeleteTREndpoint(*Endpoint) error {
	return nil
}

func (b *BaseBridge) UpdateDPIHealthy(bool) {}

func (b *BaseBridge) AddTRRule(context.Context, *DPTRRuleSpec, uint32) (uint64, error) {
	return 0, nil
}

func (b *BaseBridge) DeleteTRRuleFlow(context.Context, *DPTRRuleSpec, uint64) error {
	return nil
}
