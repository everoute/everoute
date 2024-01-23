package cache

import (
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestDeepCopy(t *testing.T) {
	src := &BaseSvc{
		SvcID:                  "src",
		SvcType:                corev1.ServiceTypeClusterIP,
		ClusterIPs:             []string{"1.1.1.1"},
		Ports:                  make(map[string]*Port),
		ExternalTrafficPolicy:  TrafficPolicyLocal,
		InternalTrafficPolicy:  TrafficPolicyCluster,
		SessionAffinity:        corev1.ServiceAffinityClientIP,
		SessionAffinityTimeout: 100000,
	}
	src.Ports["p1"] = &Port{
		Name:     "p1",
		Protocol: corev1.ProtocolTCP,
		Port:     10,
		NodePort: 100,
	}

	dst := src.DeepCopy()

	if !equalBaseSvc(src, dst) {
		t.Fatalf("deepcopy failed: src data %+v doesn't equal dst data %+v", *src, *dst)
	}
	if fmt.Sprintf("%p", src) == fmt.Sprintf("%p", dst) {
		t.Fatalf("deepcopy failed: src pointer %p is equal to dst pointer %p", src, dst)
	}
	for i := range src.Ports {
		if fmt.Sprintf("%p", src.Ports[i]) == fmt.Sprintf("%p", dst.Ports[i]) {
			t.Fatalf("deepcopy failed: src.Ports[%s] pointer %p is equal to dst.Ports[%s] pointer %p", i, src.Ports[i], i, dst.Ports[i])
		}
	}

	dstChangeString := src.DeepCopy()
	dstChangeString.SvcType = corev1.ServiceTypeLoadBalancer
	if equalBaseSvc(src, dstChangeString) {
		t.Fatalf("deepcopy failed: src.SvcType %s changed follow dst.SvcType %s", src.SvcType, dstChangeString.SvcType)
	}

	dstChangeInt := src.DeepCopy()
	dstChangeInt.SessionAffinityTimeout = 10
	if equalBaseSvc(src, dstChangeInt) {
		t.Fatalf("deepcopy failed: src.SessionAffinityTimeout %d changed follow dst.SessionAffinityTimeout %d", src.SessionAffinityTimeout, dstChangeInt.SessionAffinityTimeout)
	}

	dstChangeSlice := src.DeepCopy()
	dstChangeSlice.ClusterIPs = []string{"2.3.4.5", "1.1.1.1"}
	if equalBaseSvc(src, dstChangeSlice) {
		t.Fatalf("deepcopy failed: src.ClusterIPs %+v changed follow dst.ClusterIPs %+v", src.ClusterIPs, dstChangeSlice.ClusterIPs)
	}

	dstChangePointerSlice := src.DeepCopy()
	dstChangePointerSlice.Ports["p1"].Port = 456
	if equalBaseSvc(src, dstChangePointerSlice) {
		t.Fatalf("deepcopy failed: src.Ports %+v changed follow dst.Ports %+v", src.Ports, dstChangePointerSlice.Ports)
	}
}

func TestServicePortToPort(t *testing.T) {
	tests := []struct {
		name string
		arg  *corev1.ServicePort
		exp  *Port
	}{
		{
			name: "normal",
			arg: &corev1.ServicePort{
				Name:     "port1",
				Protocol: corev1.ProtocolTCP,
				Port:     34,
				NodePort: 90,
			},
			exp: &Port{
				Name:     "port1",
				Protocol: corev1.ProtocolTCP,
				Port:     34,
				NodePort: 90,
			},
		},
		{
			name: "input is nil",
			arg:  nil,
			exp:  nil,
		},
		{
			name: "invalid protocol",
			arg: &corev1.ServicePort{
				Name:     "port2",
				Protocol: corev1.ProtocolSCTP,
				Port:     34,
				NodePort: 90,
			},
			exp: nil,
		},
	}
	for i := range tests {
		t.Run(tests[i].name, func(t *testing.T) {
			real := servicePortToPort(tests[i].arg)
			if tests[i].exp == nil && real == nil {
				return
			}
			if tests[i].exp == nil || real == nil {
				t.Errorf("expect %+v equal to %+v", real, tests[i].exp)
				return
			}
			if *tests[i].exp != *real {
				t.Errorf("expect %+v equal to %+v", real, tests[i].exp)
			}
		})
	}
}

func equalBaseSvc(b1 *BaseSvc, b2 *BaseSvc) bool {
	if b1 == nil && b2 == nil {
		return true
	}
	if b1 == nil || b2 == nil {
		return false
	}

	if b1.SvcID != b2.SvcID {
		return false
	}

	if b1.ExternalTrafficPolicy != b2.ExternalTrafficPolicy {
		return false
	}

	if b1.InternalTrafficPolicy != b2.InternalTrafficPolicy {
		return false
	}

	if b1.SvcType != b2.SvcType {
		return false
	}

	if add, del := b1.DiffClusterIPs(b2); len(add) != 0 || len(del) != 0 {
		return false
	}

	if b1.ChangeAffinityMode(b2) || b1.ChangeAffinityTimeout(b2) {
		return false
	}

	if add, upd, del := b1.DiffPorts(b2); len(add) != 0 || len(upd) != 0 || len(del) != 0 {
		return false
	}

	return true
}
