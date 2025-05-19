package datapath

import (
	"reflect"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/assert"
	lock "github.com/viney-shih/go-lock"
	"k8s.io/klog/v2"

	trconst "github.com/everoute/everoute/pkg/constants/tr"
	"github.com/everoute/everoute/pkg/trafficredirect/action"
	"github.com/everoute/everoute/pkg/types"
)

func TestIsTREndpoint(t *testing.T) {
	ep1 := &Endpoint{BridgeName: trconst.SvcChainBridgeName}
	assert.True(t, IsTREndpoint(ep1))

	ep2 := &Endpoint{BridgeName: "br-test-policy"}
	assert.True(t, IsTREndpoint(ep2))

	ep3 := &Endpoint{BridgeName: "br-test"}
	assert.False(t, IsTREndpoint(ep3))
}

func TestAssemblyTRFlowID(t *testing.T) {
	round := uint64(5)
	seq := uint64(10)

	expected := uint64(0x2000_0000_5000_000a)
	result := assemblyTRFlowID(round, seq)
	assert.Equal(t, expected, result)
}

func TestGetTRNicFlowID(t *testing.T) {
	round := uint64(2)
	expected := uint64(0x2000_0000_2000_0000)
	result := GetTRNicFlowID(round)
	assert.Equal(t, expected, result)
}

func TestGetTRHealthyFlowID(t *testing.T) {
	round := uint64(3)
	expected := uint64(0x2000_0000_3000_0040)
	result := GetTRHealthyFlowID(round)
	assert.Equal(t, expected, result)
}

func TestIsEnableTR(t *testing.T) {
	dm := &DpManager{}
	assert.False(t, dm.IsEnableTR())

	dm.Config = &DpManagerConfig{
		TRConfig: map[string]VDSTRConfig{},
	}
	assert.False(t, dm.IsEnableTR())

	dm.Config.TRConfig["vds1"] = VDSTRConfig{}
	assert.True(t, dm.IsEnableTR())
}

func TestMustRemountTRNic(t *testing.T) {
	tests := []struct {
		name         string
		ifaceID      string
		trConfig     VDSTRConfig
		expectedCall bool
		expectedType types.NicDirect
	}{
		{
			name:    "NicOut matched",
			ifaceID: "iface-out",
			trConfig: VDSTRConfig{
				NicOut: "iface-out",
			},
			expectedCall: true,
			expectedType: types.NicOut,
		},
		{
			name:    "NicIn matched",
			ifaceID: "iface-in",
			trConfig: VDSTRConfig{
				NicIn: "iface-in",
			},
			expectedCall: true,
			expectedType: types.NicIn,
		},
		{
			name:    "No match",
			ifaceID: "unknown-iface",
			trConfig: VDSTRConfig{
				NicIn: "iface-in",
			},
			expectedCall: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			patch := gomonkey.ApplyFunc(action.MustMountTRNic, func(bridge, ifaceName, ifaceID string, nicType types.NicDirect) {
				called = true
				assert.Equal(t, "br-test", bridge)
				assert.Equal(t, "eth0", ifaceName)
				assert.Equal(t, tt.ifaceID, ifaceID)
				assert.Equal(t, tt.expectedType, nicType)
			})
			defer patch.Reset()

			dm := &DpManager{
				Config: &DpManagerConfig{
					TRConfig: map[string]VDSTRConfig{
						"vds1": tt.trConfig,
					},
					ManagedVDSMap: map[string]string{
						"vds1": "br-test",
					},
				},
			}

			ep := &Endpoint{
				InterfaceName: "eth0",
				InterfaceUUID: "uuid-123",
				BridgeName:    trconst.SvcChainBridgeName,
				IfaceID:       tt.ifaceID,
			}

			dm.mustRemountTRNic(ep)

			assert.Equal(t, tt.expectedCall, called)
		})
	}
}

type MockBridge struct {
	BaseBridge
	UpdateCalled bool
	DeleteCalled bool
	receivedEp   *Endpoint
}

func (mb *MockBridge) UpdateTREndpoint(ep *Endpoint) error {
	mb.UpdateCalled = true
	mb.receivedEp = ep
	klog.Infof("MockBridge UpdateTREndpoint called")
	return nil
}

func (mb *MockBridge) DeleteTREndpoint(ep *Endpoint) error {
	mb.DeleteCalled = true
	mb.receivedEp = ep
	klog.Infof("MockBridge DeleteTREndpoint called")
	return nil
}

func TestAddTREndpoint(t *testing.T) {
	policySuffix := "-policy"

	dm := &DpManager{
		Config: &DpManagerConfig{
			ManagedVDSMap: map[string]string{
				"vds1": "br1",
			},
			TRConfig: map[string]VDSTRConfig{
				"vds1": {NicIn: "nic-in", NicOut: "nic-out"},
			},
		},
		BridgeChainMap: map[string]map[string]Bridge{
			"vds1": {
				POLICY_BRIDGE_KEYWORD: &MockBridge{},
			},
		},
	}

	// patch mustRemountTRNic，便于检测调用
	var remountCalled bool
	patches := gomonkey.ApplyPrivateMethod(reflect.TypeOf(dm), "mustRemountTRNic", func(*DpManager, *Endpoint) {
		remountCalled = true
	})
	defer patches.Reset()

	tests := []struct {
		name          string
		ep            *Endpoint
		expectRemount bool
		expectUpdate  bool
		expectError   bool
	}{
		{
			name: "Extend is nil",
			ep: &Endpoint{
				BridgeName:    "anything",
				InterfaceName: "if1",
				InterfaceUUID: "uuid1",
			},
			expectRemount: false,
			expectUpdate:  false,
			expectError:   false,
		},
		{
			name: "Extend.IfaceID is empty",
			ep: &Endpoint{
				BridgeName:    "anything",
				InterfaceName: "if2",
				InterfaceUUID: "uuid2",
				IfaceID:       "",
			},
			expectRemount: false,
			expectUpdate:  false,
			expectError:   false,
		},
		{
			name: "BridgeName equals SvcChainBridgeName calls mustRemountTRNic",
			ep: &Endpoint{
				BridgeName:    trconst.SvcChainBridgeName,
				InterfaceName: "if3",
				InterfaceUUID: "uuid3",
				IfaceID:       "nic-out",
			},
			expectRemount: true,
			expectUpdate:  false,
			expectError:   false,
		},
		{
			name: "BridgeName without policy suffix, skip process",
			ep: &Endpoint{
				BridgeName:    "somebridge",
				InterfaceName: "if4",
				InterfaceUUID: "uuid4",
				IfaceID:       "nic-out",
			},
			expectRemount: false,
			expectUpdate:  false,
			expectError:   false,
		},
		{
			name: "BridgeName with policy suffix but no matching ManagedVDSMap",
			ep: &Endpoint{
				BridgeName:    "notfound" + PolicyBridgeSuffix,
				InterfaceName: "if5",
				InterfaceUUID: "uuid5",
				IfaceID:       "nic-out",
			},
			expectRemount: false,
			expectUpdate:  false,
			expectError:   false,
		},
		{
			name: "BridgeName with policy suffix and matching ManagedVDSMap, call UpdateTREndpoint",
			ep: &Endpoint{
				BridgeName:    "br1" + policySuffix,
				InterfaceName: "if6",
				InterfaceUUID: "uuid6",
				IfaceID:       "nic-out",
			},
			expectRemount: false,
			expectUpdate:  true,
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			remountCalled = false
			mb := dm.BridgeChainMap["vds1"][POLICY_BRIDGE_KEYWORD].(*MockBridge)
			mb.UpdateCalled = false

			err := dm.AddTREndpoint(tt.ep)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tt.expectRemount, remountCalled, "mustRemountTRNic called")
			assert.Equal(t, tt.expectUpdate, mb.UpdateCalled, "UpdateTREndpoint called")
		})
	}
}

func TestUpdateTREndpoint(t *testing.T) {
	dm := &DpManager{
		Config: &DpManagerConfig{
			ManagedVDSMap: map[string]string{
				"vds1": "br1",
			},
		},
		BridgeChainMap: map[string]map[string]Bridge{
			"vds1": {
				POLICY_BRIDGE_KEYWORD: &MockBridge{},
			},
		},
	}

	t.Run("nil extend", func(t *testing.T) {
		ep := &Endpoint{InterfaceName: "ep1", BridgeName: "br1-policy"}
		err := dm.UpdateTREndpoint(ep)
		assert.NoError(t, err)
		mb := dm.BridgeChainMap["vds1"][POLICY_BRIDGE_KEYWORD].(*MockBridge)
		assert.False(t, mb.UpdateCalled)
	})

	t.Run("ifaceID empty", func(t *testing.T) {
		ep := &Endpoint{InterfaceName: "ep1", BridgeName: "br1-policy"}
		err := dm.UpdateTREndpoint(ep)
		assert.NoError(t, err)
		mb := dm.BridgeChainMap["vds1"][POLICY_BRIDGE_KEYWORD].(*MockBridge)
		assert.False(t, mb.UpdateCalled)
	})

	t.Run("bridge is svcChainBridge", func(t *testing.T) {
		ep := &Endpoint{InterfaceName: "ep1", BridgeName: trconst.SvcChainBridgeName, IfaceID: "id"}
		err := dm.UpdateTREndpoint(ep)
		assert.NoError(t, err)
		mb := dm.BridgeChainMap["vds1"][POLICY_BRIDGE_KEYWORD].(*MockBridge)
		assert.False(t, mb.UpdateCalled)
	})

	t.Run("bridge suffix no policy", func(t *testing.T) {
		ep := &Endpoint{InterfaceName: "ep1", BridgeName: "br1-noPolicy", IfaceID: "id"}
		err := dm.UpdateTREndpoint(ep)
		assert.NoError(t, err)
		mb := dm.BridgeChainMap["vds1"][POLICY_BRIDGE_KEYWORD].(*MockBridge)
		assert.False(t, mb.UpdateCalled)
	})

	t.Run("bridge managed and UpdateTREndpoint called", func(t *testing.T) {
		ep := &Endpoint{InterfaceName: "ep1", BridgeName: "br1-policy", IfaceID: "id"}
		mb := dm.BridgeChainMap["vds1"][POLICY_BRIDGE_KEYWORD].(*MockBridge)
		mb.UpdateCalled = false
		mb.receivedEp = nil

		err := dm.UpdateTREndpoint(ep)
		assert.NoError(t, err)
		assert.True(t, mb.UpdateCalled)
		assert.Equal(t, ep, mb.receivedEp)
	})

	t.Run("bridge managed but localBridge not match", func(t *testing.T) {
		ep := &Endpoint{InterfaceName: "ep1", BridgeName: "br2-policy", IfaceID: "id"}
		mb := dm.BridgeChainMap["vds1"][POLICY_BRIDGE_KEYWORD].(*MockBridge)
		mb.UpdateCalled = false

		err := dm.UpdateTREndpoint(ep)
		assert.NoError(t, err)
		assert.False(t, mb.UpdateCalled)
	})
}

func TestDeleteTREndpoint(t *testing.T) {
	dm := &DpManager{
		Config: &DpManagerConfig{
			ManagedVDSMap: map[string]string{
				"vds1": "br1",
			},
		},
		BridgeChainMap: map[string]map[string]Bridge{
			"vds1": {
				POLICY_BRIDGE_KEYWORD: &MockBridge{},
			},
		},
	}

	t.Run("nil extend", func(t *testing.T) {
		ep := &Endpoint{InterfaceName: "ep1", BridgeName: "br1-policy"}
		err := dm.DeleteTREndpoint(ep)
		assert.NoError(t, err)
		mb := dm.BridgeChainMap["vds1"][POLICY_BRIDGE_KEYWORD].(*MockBridge)
		assert.False(t, mb.DeleteCalled)
	})

	t.Run("ifaceID empty", func(t *testing.T) {
		ep := &Endpoint{InterfaceName: "ep1", BridgeName: "br1-policy"}
		err := dm.DeleteTREndpoint(ep)
		assert.NoError(t, err)
		mb := dm.BridgeChainMap["vds1"][POLICY_BRIDGE_KEYWORD].(*MockBridge)
		assert.False(t, mb.DeleteCalled)
	})

	t.Run("bridge is svcChainBridge", func(t *testing.T) {
		ep := &Endpoint{InterfaceName: "ep1", BridgeName: trconst.SvcChainBridgeName, IfaceID: "id"}
		err := dm.DeleteTREndpoint(ep)
		assert.NoError(t, err)
		mb := dm.BridgeChainMap["vds1"][POLICY_BRIDGE_KEYWORD].(*MockBridge)
		assert.False(t, mb.DeleteCalled)
	})

	t.Run("bridge suffix no policy", func(t *testing.T) {
		ep := &Endpoint{InterfaceName: "ep1", BridgeName: "br1-noPolicy", IfaceID: "id"}
		err := dm.DeleteTREndpoint(ep)
		assert.NoError(t, err)
		mb := dm.BridgeChainMap["vds1"][POLICY_BRIDGE_KEYWORD].(*MockBridge)
		assert.False(t, mb.DeleteCalled)
	})

	t.Run("bridge managed and DeleteTREndpoint called", func(t *testing.T) {
		ep := &Endpoint{InterfaceName: "ep1", BridgeName: "br1-policy", IfaceID: "id"}
		mb := dm.BridgeChainMap["vds1"][POLICY_BRIDGE_KEYWORD].(*MockBridge)
		mb.DeleteCalled = false
		mb.receivedEp = nil

		err := dm.DeleteTREndpoint(ep)
		assert.NoError(t, err)
		assert.True(t, mb.DeleteCalled)
		assert.Equal(t, ep, mb.receivedEp)
	})

	t.Run("bridge managed but localBridge not match", func(t *testing.T) {
		ep := &Endpoint{InterfaceName: "ep1", BridgeName: "br2-policy", IfaceID: "id"}
		mb := dm.BridgeChainMap["vds1"][POLICY_BRIDGE_KEYWORD].(*MockBridge)
		mb.DeleteCalled = false

		err := dm.DeleteTREndpoint(ep)
		assert.NoError(t, err)
		assert.False(t, mb.DeleteCalled)
	})
}

type MockBridge2 struct {
	BaseBridge
	UpdateDPIHealthyCalled bool
	ReceivedHealthy        bool
}

func (mb *MockBridge2) UpdateDPIHealthy(healthy bool) {
	mb.UpdateDPIHealthyCalled = true
	mb.ReceivedHealthy = healthy
}

func TestProcessDPIHealthyStatus(t *testing.T) {
	mockBridge := &MockBridge2{}

	dm := &DpManager{
		flowReplayMutex: lock.NewCASMutex(),
		Config: &DpManagerConfig{
			TRConfig: map[string]VDSTRConfig{
				"vds1": {},
			},
		},
		BridgeChainMap: map[string]map[string]Bridge{
			"vds1": {
				POLICY_BRIDGE_KEYWORD: mockBridge,
			},
		},
	}

	// 测试 DPIAlive
	dm.ProcessDPIHealthyStatus(types.DPIAlive)
	if !mockBridge.UpdateDPIHealthyCalled {
		t.Errorf("UpdateDPIHealthy was not called")
	}
	if mockBridge.ReceivedHealthy != true {
		t.Errorf("Expected healthy true, got false")
	}

	mockBridge.UpdateDPIHealthyCalled = false
	mockBridge.ReceivedHealthy = false

	// 测试 DPIDead
	dm.ProcessDPIHealthyStatus(types.DPIDead)
	if !mockBridge.UpdateDPIHealthyCalled {
		t.Errorf("UpdateDPIHealthy was not called")
	}
	if mockBridge.ReceivedHealthy != false {
		t.Errorf("Expected healthy false, got true")
	}

	mockBridge.UpdateDPIHealthyCalled = false
	mockBridge.ReceivedHealthy = false

	// 测试 DPIUnknown
	dm.ProcessDPIHealthyStatus(types.DPIUnknown)
	if !mockBridge.UpdateDPIHealthyCalled {
		t.Errorf("UpdateDPIHealthy was not called")
	}
	if mockBridge.ReceivedHealthy != false {
		t.Errorf("Expected healthy false for DPIUnknown, got true")
	}

	// 测试 TRConfig 为空
	dm.Config.TRConfig = map[string]VDSTRConfig{}
	mockBridge.UpdateDPIHealthyCalled = false
	dm.ProcessDPIHealthyStatus(types.DPIAlive)
	if mockBridge.UpdateDPIHealthyCalled {
		t.Errorf("UpdateDPIHealthy should NOT be called when TRConfig is empty")
	}
}
