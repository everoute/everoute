package v1alpha1

import (
	"testing"

	"github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/types"
)

func TestGroupMemberEqual(t *testing.T) {
	cases := []struct {
		name string
		aGM  *GroupMember
		bGM  *GroupMember
		exp  bool
	}{
		{
			name: "equal",
			aGM: &GroupMember{
				EndpointReference: EndpointReference{
					ExternalIDName:  "test",
					ExternalIDValue: "value-a",
				},
				EndpointAgent: []string{"agent1", "agent2"},
				IPs:           []types.IPAddress{"192.168.1.1", "10.10.10.1"},
				Ports: []v1alpha1.NamedPort{
					{
						Name:     "port1",
						Port:     34,
						Protocol: v1alpha1.ProtocolTCP,
					},
					{
						Name:     "port2",
						Protocol: v1alpha1.ProtocolICMP,
					},
				},
			},
			bGM: &GroupMember{
				EndpointReference: EndpointReference{
					ExternalIDName:  "test",
					ExternalIDValue: "value-a",
				},
				EndpointAgent: []string{"agent2", "agent1"},
				IPs:           []types.IPAddress{"10.10.10.1", "192.168.1.1"},
				Ports: []v1alpha1.NamedPort{
					{
						Name:     "port1",
						Port:     34,
						Protocol: v1alpha1.ProtocolTCP,
					},
					{
						Name:     "port2",
						Protocol: v1alpha1.ProtocolICMP,
					},
				},
			},
			exp: true,
		},
		{
			name: "ip num doesn't equal", 
			aGM: &GroupMember{
				EndpointReference: EndpointReference{
					ExternalIDName:  "test",
					ExternalIDValue: "value-a",
				},
				EndpointAgent: []string{"agent1", "agent2"},
				IPs:           []types.IPAddress{},
				Ports: []v1alpha1.NamedPort{
					{
						Name:     "port1",
						Port:     34,
						Protocol: v1alpha1.ProtocolTCP,
					},
					{
						Name:     "port2",
						Protocol: v1alpha1.ProtocolICMP,
					},
				},
			},
			bGM: &GroupMember{
				EndpointReference: EndpointReference{
					ExternalIDName:  "test",
					ExternalIDValue: "value-a",
				},
				EndpointAgent: []string{"agent2", "agent1"},
				IPs:           []types.IPAddress{"10.10.10.1", "192.168.1.1"},
				Ports: []v1alpha1.NamedPort{
					{
						Name:     "port1",
						Port:     34,
						Protocol: v1alpha1.ProtocolTCP,
					},
					{
						Name:     "port2",
						Protocol: v1alpha1.ProtocolICMP,
					},
				},
			},
			exp: false,
		},
		{
			name: "ip doesn't equal", 
			aGM: &GroupMember{
				EndpointReference: EndpointReference{
					ExternalIDName:  "test",
					ExternalIDValue: "value-a",
				},
				EndpointAgent: []string{"agent1", "agent2"},
				IPs:           []types.IPAddress{"192.168.1.1", "10.10.10.2"},
				Ports: []v1alpha1.NamedPort{
					{
						Name:     "port1",
						Port:     34,
						Protocol: v1alpha1.ProtocolTCP,
					},
					{
						Name:     "port2",
						Protocol: v1alpha1.ProtocolICMP,
					},
				},
			},
			bGM: &GroupMember{
				EndpointReference: EndpointReference{
					ExternalIDName:  "test",
					ExternalIDValue: "value-a",
				},
				EndpointAgent: []string{"agent2", "agent1"},
				IPs:           []types.IPAddress{"10.10.10.1", "192.168.1.1"},
				Ports: []v1alpha1.NamedPort{
					{
						Name:     "port1",
						Port:     34,
						Protocol: v1alpha1.ProtocolTCP,
					},
					{
						Name:     "port2",
						Protocol: v1alpha1.ProtocolICMP,
					},
				},
			},
			exp: false,
		},
		{
			name: "groupmember is nil", 
			aGM: &GroupMember{
				EndpointReference: EndpointReference{
					ExternalIDName:  "test",
					ExternalIDValue: "value-a",
				},
				EndpointAgent: []string{"agent1", "agent2"},
				IPs:           []types.IPAddress{"192.168.1.1"},
				Ports: []v1alpha1.NamedPort{
					{
						Name:     "port1",
						Port:     34,
						Protocol: v1alpha1.ProtocolTCP,
					},
					{
						Name:     "port2",
						Protocol: v1alpha1.ProtocolICMP,
					},
				},
			},
			bGM: nil,
			exp: false,
		},
		{
			name: "agent num doesn't equal", 
			aGM: &GroupMember{
				EndpointReference: EndpointReference{
					ExternalIDName:  "test",
					ExternalIDValue: "value-a",
				},
				EndpointAgent: []string{"agent1"},
				IPs:           []types.IPAddress{"192.168.1.1", "10.10.10.2"},
				Ports: []v1alpha1.NamedPort{
					{
						Name:     "port1",
						Port:     34,
						Protocol: v1alpha1.ProtocolTCP,
					},
					{
						Name:     "port2",
						Protocol: v1alpha1.ProtocolICMP,
					},
				},
			},
			bGM: &GroupMember{
				EndpointReference: EndpointReference{
					ExternalIDName:  "test",
					ExternalIDValue: "value-a",
				},
				EndpointAgent: []string{"agent2", "agent1"},
				IPs:           []types.IPAddress{"10.10.10.2", "192.168.1.1"},
				Ports: []v1alpha1.NamedPort{
					{
						Name:     "port1",
						Port:     34,
						Protocol: v1alpha1.ProtocolTCP,
					},
					{
						Name:     "port2",
						Protocol: v1alpha1.ProtocolICMP,
					},
				},
			},
			exp: false,
		},
		{
			name: "agent doesn't equal", 
			aGM: &GroupMember{
				EndpointReference: EndpointReference{
					ExternalIDName:  "test",
					ExternalIDValue: "value-a",
				},
				EndpointAgent: []string{"agent3", "agent4"},
				IPs:           []types.IPAddress{"192.168.1.1", "10.10.10.2"},
				Ports: []v1alpha1.NamedPort{
					{
						Name:     "port1",
						Port:     34,
						Protocol: v1alpha1.ProtocolTCP,
					},
					{
						Name:     "port2",
						Protocol: v1alpha1.ProtocolICMP,
					},
				},
			},
			bGM: &GroupMember{
				EndpointReference: EndpointReference{
					ExternalIDName:  "test",
					ExternalIDValue: "value-a",
				},
				EndpointAgent: []string{"agent2", "agent1"},
				IPs:           []types.IPAddress{"10.10.10.2", "192.168.1.1"},
				Ports: []v1alpha1.NamedPort{
					{
						Name:     "port1",
						Port:     34,
						Protocol: v1alpha1.ProtocolTCP,
					},
					{
						Name:     "port2",
						Protocol: v1alpha1.ProtocolICMP,
					},
				},
			},
			exp: false,
		},
		{
			name: "port num doesn't equal", 
			aGM: &GroupMember{
				EndpointReference: EndpointReference{
					ExternalIDName:  "test",
					ExternalIDValue: "value-a",
				},
				EndpointAgent: []string{"agent1", "agent2"},
				IPs:           []types.IPAddress{"192.168.1.1", "10.10.10.2"},
				Ports: []v1alpha1.NamedPort{
					{
						Name:     "port1",
						Port:     34,
						Protocol: v1alpha1.ProtocolTCP,
					},
					{
						Name:     "port2",
						Protocol: v1alpha1.ProtocolICMP,
					},
				},
			},
			bGM: &GroupMember{
				EndpointReference: EndpointReference{
					ExternalIDName:  "test",
					ExternalIDValue: "value-a",
				},
				EndpointAgent: []string{"agent2", "agent1"},
				IPs:           []types.IPAddress{"10.10.10.2", "192.168.1.1"},
				Ports: []v1alpha1.NamedPort{
					{
						Name:     "port2",
						Protocol: v1alpha1.ProtocolICMP,
					},
				},
			},
			exp: false,
		},
		{
			name: "port doesn't equal", 
			aGM: &GroupMember{
				EndpointReference: EndpointReference{
					ExternalIDName:  "test",
					ExternalIDValue: "value-a",
				},
				EndpointAgent: []string{"agent1"},
				IPs:           []types.IPAddress{"192.168.1.1", "10.10.10.2"},
				Ports: []v1alpha1.NamedPort{
					{
						Name:     "port1",
						Port:     34,
						Protocol: v1alpha1.ProtocolTCP,
					},
					{
						Name:     "port2",
						Protocol: v1alpha1.ProtocolICMP,
					},
				},
			},
			bGM: &GroupMember{
				EndpointReference: EndpointReference{
					ExternalIDName:  "test",
					ExternalIDValue: "value-a",
				},
				EndpointAgent: []string{"agent2", "agent1"},
				IPs:           []types.IPAddress{"10.10.10.2", "192.168.1.1"},
				Ports: []v1alpha1.NamedPort{
					{
						Name:     "port1",
						Port:     34,
						Protocol: v1alpha1.ProtocolUDP,
					},
					{
						Name:     "port2",
						Protocol: v1alpha1.ProtocolICMP,
					},
				},
			},
			exp: false,
		},
		{
			name: "endpointReference doesn't equal", 
			aGM: &GroupMember{
				EndpointReference: EndpointReference{
					ExternalIDName:  "test",
					ExternalIDValue: "value-a",
				},
				EndpointAgent: []string{"agent1"},
				IPs:           []types.IPAddress{"192.168.1.1", "10.10.10.2"},
				Ports: []v1alpha1.NamedPort{
					{
						Name:     "port1",
						Port:     34,
						Protocol: v1alpha1.ProtocolTCP,
					},
					{
						Name:     "port2",
						Protocol: v1alpha1.ProtocolICMP,
					},
				},
			},
			bGM: &GroupMember{
				EndpointReference: EndpointReference{
					ExternalIDName:  "test",
					ExternalIDValue: "value-b",
				},
				EndpointAgent: []string{"agent2", "agent1"},
				IPs:           []types.IPAddress{"10.10.10.2", "192.168.1.1"},
				Ports: []v1alpha1.NamedPort{
					{
						Name:     "port1",
						Port:     34,
						Protocol: v1alpha1.ProtocolTCP,
					},
					{
						Name:     "port2",
						Protocol: v1alpha1.ProtocolICMP,
					},
				},
			},
			exp: false,
		},
	}

	for _, c := range cases {
		res := c.aGM.Equal(c.bGM)
		if res != c.exp {
			t.Errorf("test %s failed, exp is %v, real is %v", c.name, c.exp, res)
		}
	}
}
