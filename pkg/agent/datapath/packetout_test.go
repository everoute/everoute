package datapath

import (
	"net"
	"testing"

	openflow "antrea.io/libOpenflow/openflow15"
)

func TestNewProbePacketOutIncludesControllerInPort(t *testing.T) {
	packetOut := newProbePacketOut(7, 0, net.HardwareAddr{0x7a, 0x93, 0x8c, 0x0b, 0x0e, 0xed}, net.ParseIP("125.125.125.4"))

	if len(packetOut.Match.Fields) != 1 {
		t.Fatalf("expected one PacketOut match field, got %d", len(packetOut.Match.Fields))
	}
	field := packetOut.Match.Fields[0]
	if field.Class != openflow.OXM_CLASS_OPENFLOW_BASIC || field.Field != openflow.OXM_FIELD_IN_PORT {
		t.Fatalf("expected in_port match field, got class=%#x field=%#x", field.Class, field.Field)
	}

	inPort, ok := field.Value.(*openflow.InPortField)
	if !ok {
		t.Fatalf("expected InPortField value, got %T", field.Value)
	}
	if inPort.InPort != openflow.P_CONTROLLER {
		t.Fatalf("expected PacketOut in_port %#x, got %#x", openflow.P_CONTROLLER, inPort.InPort)
	}
}
