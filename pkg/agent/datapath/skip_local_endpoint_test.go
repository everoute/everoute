package datapath

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSkipLocalEndpoint(t *testing.T) {
	dp := &DpManager{
		Info: &DpManagerInfo{
			BridgeName:  "cni-br",
			LocalGwName: "local-gw",
		},
	}

	tests := []struct {
		name     string
		endpoint *Endpoint
		want     bool
	}{
		{
			name: "ovs bridge local interface",
			endpoint: &Endpoint{
				InterfaceName: "ovsbr0",
				BridgeName:    "ovsbr0",
				PortNo:        0xfffe,
			},
			want: true,
		},
		{
			name: "ordinary endpoint",
			endpoint: &Endpoint{
				InterfaceName: "tap0",
				BridgeName:    "ovsbr0",
				PortNo:        10,
			},
			want: false,
		},
		{
			name: "cni bridge default interface",
			endpoint: &Endpoint{
				InterfaceName: "cni-br",
				BridgeName:    "ovsbr0",
				PortNo:        1,
			},
			want: true,
		},
		{
			name: "cni local gateway",
			endpoint: &Endpoint{
				InterfaceName: "local-gw",
				BridgeName:    "ovsbr0",
				PortNo:        2,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, dp.skipLocalEndpoint(tt.endpoint))
		})
	}
}
