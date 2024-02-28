package proxy

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestIsNodePortSvc(t *testing.T) {
	tests := []struct {
		name    string
		svcType corev1.ServiceType
		needNP  bool
		exp     bool
	}{
		{
			name:    "nodeport svc",
			svcType: corev1.ServiceTypeNodePort,
			exp:     true,
		},
		{
			name:    "lb svc",
			svcType: corev1.ServiceTypeLoadBalancer,
			exp:     true,
		},
		{
			name:    "clusterIP svc",
			svcType: corev1.ServiceTypeClusterIP,
			exp:     false,
		},
		{
			name:    "externalName svc",
			svcType: corev1.ServiceTypeExternalName,
			exp:     false,
		},
	}

	for i := range tests {
		svc := assembleSvc(tests[i].svcType, 1, 1)
		if tests[i].svcType == corev1.ServiceTypeLoadBalancer {
			svc.Spec.AllocateLoadBalancerNodePorts = &tests[i].needNP
		}
		res := isNodePortSvc(svc)
		if res != tests[i].exp {
			t.Errorf("test %s failed, exp is %v, real is %v", tests[i].name, tests[i].exp, res)
		}
	}
}

func TestGetNodePortsByProtocol(t *testing.T) {
	tests := []struct {
		name     string
		argProto corev1.Protocol
		proto    corev1.Protocol
		nodePort int32
		isEmpty  bool
	}{
		{
			name:     "tcp",
			argProto: corev1.ProtocolTCP,
			proto:    corev1.ProtocolTCP,
			nodePort: genNodePortNumber(),
			isEmpty:  false,
		},
		{
			name:     "port is tcp but filter udp",
			argProto: corev1.ProtocolUDP,
			proto:    corev1.ProtocolTCP,
			nodePort: genNodePortNumber(),
			isEmpty:  true,
		},
		{
			name:     "udp",
			argProto: corev1.ProtocolUDP,
			proto:    corev1.ProtocolUDP,
			nodePort: genNodePortNumber(),
			isEmpty:  false,
		},
		{
			name:     "port proto is sctp, but filter udp",
			argProto: corev1.ProtocolUDP,
			proto:    corev1.ProtocolSCTP,
			nodePort: genNodePortNumber(),
			isEmpty:  true,
		},
		{
			name:     "nodeport is 0",
			argProto: corev1.ProtocolUDP,
			proto:    corev1.ProtocolUDP,
			isEmpty:  true,
		},
	}

	for i := range tests {
		svc := assembleSvc(corev1.ServiceTypeLoadBalancer, 0, 1)
		svc.Spec.Ports[0] = corev1.ServicePort{
			Protocol: tests[i].proto,
			NodePort: tests[i].nodePort,
		}
		res := getNodePortsByProtocol(svc, tests[i].argProto)
		resIsEmpty := (res.Len() == 0)
		if resIsEmpty != tests[i].isEmpty {
			t.Errorf("test %s failed", tests[i].name)
		}
	}
}
