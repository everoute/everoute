package cache

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ertype "github.com/everoute/everoute/pkg/types"
)

func TestServiceToSvcLBs(t *testing.T) {
	internalTPLocal := corev1.ServiceInternalTrafficPolicyLocal
	timeout := int32(900)
	invalidTimeout := int32(-9)
	cases := []struct {
		name     string
		svc      *corev1.Service
		proxyAll bool
		exp      []*SvcLB
		expErr   bool
	}{
		{
			name:     "clusterIP svc with proxyAll",
			proxyAll: true,
			svc: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "svc",
					Namespace: "ns",
				},
				Spec: corev1.ServiceSpec{
					Type:       corev1.ServiceTypeClusterIP,
					ClusterIP:  "10.10.1.1",
					ClusterIPs: []string{"10.10.1.1", "fe23::90"},
					Ports: []corev1.ServicePort{
						{
							Name:     "ssh",
							Protocol: corev1.ProtocolTCP,
							Port:     22,
						},
						{
							Name:     "dhcp",
							Protocol: corev1.ProtocolUDP,
							Port:     53,
						},
					},
					ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
					SessionAffinity:       corev1.ServiceAffinityNone,
				},
			},
			exp: []*SvcLB{
				&SvcLB{
					SvcID: "ns/svc",
					IP:    "10.10.1.1",
					Port: Port{
						Name:     "ssh",
						Protocol: corev1.ProtocolTCP,
						Port:     22,
					},
					TrafficPolicy:   ertype.TrafficPolicyCluster,
					SessionAffinity: corev1.ServiceAffinityNone,
				},
				&SvcLB{
					SvcID: "ns/svc",
					IP:    "10.10.1.1",
					Port: Port{
						Name:     "dhcp",
						Protocol: corev1.ProtocolUDP,
						Port:     53,
					},
					TrafficPolicy:   ertype.TrafficPolicyCluster,
					SessionAffinity: corev1.ServiceAffinityNone,
				},
			},
			expErr: false,
		},
		{
			name:     "clusterIP svc without proxyAll",
			proxyAll: false,
			svc: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "svc",
					Namespace: "ns",
				},
				Spec: corev1.ServiceSpec{
					Type:       corev1.ServiceTypeClusterIP,
					ClusterIP:  "10.10.1.1",
					ClusterIPs: []string{"10.10.1.1", "fe23::90"},
					Ports: []corev1.ServicePort{
						{
							Name:     "ssh",
							Protocol: corev1.ProtocolTCP,
							Port:     22,
						},
						{
							Name:     "dhcp",
							Protocol: corev1.ProtocolUDP,
							Port:     53,
						},
					},
					ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
					SessionAffinity:       corev1.ServiceAffinityNone,
				},
			},
			exp: []*SvcLB{
				&SvcLB{
					SvcID: "ns/svc",
					IP:    "10.10.1.1",
					Port: Port{
						Name:     "ssh",
						Protocol: corev1.ProtocolTCP,
						Port:     22,
					},
					TrafficPolicy:   ertype.TrafficPolicyCluster,
					SessionAffinity: corev1.ServiceAffinityNone,
				},
				&SvcLB{
					SvcID: "ns/svc",
					IP:    "10.10.1.1",
					Port: Port{
						Name:     "dhcp",
						Protocol: corev1.ProtocolUDP,
						Port:     53,
					},
					TrafficPolicy:   ertype.TrafficPolicyCluster,
					SessionAffinity: corev1.ServiceAffinityNone,
				},
			},
			expErr: false,
		},
		{
			name:     "nodeport svc with proxyAll",
			proxyAll: true,
			svc: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "svc",
					Namespace: "ns",
				},
				Spec: corev1.ServiceSpec{
					Type:       corev1.ServiceTypeNodePort,
					ClusterIP:  "10.10.1.1",
					ClusterIPs: []string{"10.10.1.1", "fe23::90"},
					Ports: []corev1.ServicePort{
						{
							Name:     "ssh",
							Protocol: corev1.ProtocolTCP,
							NodePort: 33100,
							Port:     22,
						},
						{
							Name:     "dhcp",
							Protocol: corev1.ProtocolUDP,
							Port:     53,
							NodePort: 45666,
						},
					},
					ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
					SessionAffinity:       corev1.ServiceAffinityClientIP,
				},
			},
			exp: []*SvcLB{
				&SvcLB{
					SvcID: "ns/svc",
					IP:    "10.10.1.1",
					Port: Port{
						Name:     "ssh",
						Protocol: corev1.ProtocolTCP,
						Port:     22,
					},
					TrafficPolicy:          ertype.TrafficPolicyCluster,
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: DefaultSessionAffinityTimeout,
				},
				&SvcLB{
					SvcID: "ns/svc",
					IP:    "10.10.1.1",
					Port: Port{
						Name:     "dhcp",
						Protocol: corev1.ProtocolUDP,
						Port:     53,
					},
					TrafficPolicy:          ertype.TrafficPolicyCluster,
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: DefaultSessionAffinityTimeout,
				},
				&SvcLB{
					SvcID: "ns/svc",
					Port: Port{
						Name:     "ssh",
						Protocol: corev1.ProtocolTCP,
						NodePort: 33100,
					},
					TrafficPolicy:          ertype.TrafficPolicyLocal,
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: DefaultSessionAffinityTimeout,
				},
				&SvcLB{
					SvcID: "ns/svc",
					Port: Port{
						Name:     "dhcp",
						Protocol: corev1.ProtocolUDP,
						NodePort: 45666,
					},
					TrafficPolicy:          ertype.TrafficPolicyLocal,
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: DefaultSessionAffinityTimeout,
				},
			},
			expErr: false,
		},
		{
			name:     "nodeport svc without proxyAll",
			proxyAll: false,
			svc: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "svc",
					Namespace: "ns",
				},
				Spec: corev1.ServiceSpec{
					Type:       corev1.ServiceTypeNodePort,
					ClusterIP:  "10.10.1.1",
					ClusterIPs: []string{"10.10.1.1", "fe23::90"},
					Ports: []corev1.ServicePort{
						{
							Name:     "ssh",
							Protocol: corev1.ProtocolTCP,
							NodePort: 33100,
							Port:     22,
						},
						{
							Name:     "dhcp",
							Protocol: corev1.ProtocolUDP,
							Port:     53,
							NodePort: 45666,
						},
					},
					ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
					SessionAffinity:       corev1.ServiceAffinityClientIP,
				},
			},
			exp: []*SvcLB{
				&SvcLB{
					SvcID: "ns/svc",
					IP:    "10.10.1.1",
					Port: Port{
						Name:     "ssh",
						Protocol: corev1.ProtocolTCP,
						Port:     22,
					},
					TrafficPolicy:          ertype.TrafficPolicyCluster,
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: DefaultSessionAffinityTimeout,
				},
				&SvcLB{
					SvcID: "ns/svc",
					IP:    "10.10.1.1",
					Port: Port{
						Name:     "dhcp",
						Protocol: corev1.ProtocolUDP,
						Port:     53,
					},
					TrafficPolicy:          ertype.TrafficPolicyCluster,
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: DefaultSessionAffinityTimeout,
				},
			},
			expErr: false,
		},
		{
			name:     "lb svc without proxyAll",
			proxyAll: false,
			svc: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "svc",
					Namespace: "ns",
				},
				Spec: corev1.ServiceSpec{
					Type:       corev1.ServiceTypeLoadBalancer,
					ClusterIP:  "10.10.1.1",
					ClusterIPs: []string{"10.10.1.1", "fe23::90"},
					Ports: []corev1.ServicePort{
						{
							Name:     "ssh",
							Protocol: corev1.ProtocolTCP,
							NodePort: 33100,
							Port:     22,
						},
						{
							Name:     "dhcp",
							Protocol: corev1.ProtocolUDP,
							Port:     53,
							NodePort: 45666,
						},
					},
					ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
					SessionAffinity:       corev1.ServiceAffinityClientIP,
				},
				Status: corev1.ServiceStatus{
					LoadBalancer: corev1.LoadBalancerStatus{
						Ingress: []corev1.LoadBalancerIngress{
							{
								IP: "192.1.1.1",
							},
							{
								IP: "192.1.1.2",
							},
						},
					},
				},
			},
			exp: []*SvcLB{
				&SvcLB{
					SvcID: "ns/svc",
					IP:    "10.10.1.1",
					Port: Port{
						Name:     "ssh",
						Protocol: corev1.ProtocolTCP,
						Port:     22,
					},
					TrafficPolicy:          ertype.TrafficPolicyCluster,
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: DefaultSessionAffinityTimeout,
				},
				&SvcLB{
					SvcID: "ns/svc",
					IP:    "10.10.1.1",
					Port: Port{
						Name:     "dhcp",
						Protocol: corev1.ProtocolUDP,
						Port:     53,
					},
					TrafficPolicy:          ertype.TrafficPolicyCluster,
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: DefaultSessionAffinityTimeout,
				},
			},
			expErr: false,
		},
		{
			name:     "lb svc with proxyAll",
			proxyAll: true,
			svc: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "svc",
					Namespace: "ns",
				},
				Spec: corev1.ServiceSpec{
					Type:       corev1.ServiceTypeLoadBalancer,
					ClusterIP:  "10.10.1.1",
					ClusterIPs: []string{"10.10.1.1", "fe23::90"},
					Ports: []corev1.ServicePort{
						{
							Name:     "ssh",
							Protocol: corev1.ProtocolTCP,
							NodePort: 33100,
							Port:     22,
						},
					},
					ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyCluster,
					SessionAffinity:       corev1.ServiceAffinityClientIP,
					InternalTrafficPolicy: &internalTPLocal,
				},
				Status: corev1.ServiceStatus{
					LoadBalancer: corev1.LoadBalancerStatus{
						Ingress: []corev1.LoadBalancerIngress{
							{
								IP: "192.1.1.1",
							},
							{
								IP: "192.1.1.2",
							},
						},
					},
				},
			},
			exp: []*SvcLB{
				&SvcLB{
					SvcID: "ns/svc",
					IP:    "10.10.1.1",
					Port: Port{
						Name:     "ssh",
						Protocol: corev1.ProtocolTCP,
						Port:     22,
					},
					TrafficPolicy:          ertype.TrafficPolicyLocal,
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: DefaultSessionAffinityTimeout,
				},
				&SvcLB{
					SvcID:  "ns/svc",
					IP:     "192.1.1.1",
					IsLBIP: true,
					Port: Port{
						Name:     "ssh",
						Protocol: corev1.ProtocolTCP,
						Port:     22,
					},
					TrafficPolicy:          ertype.TrafficPolicyCluster,
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: DefaultSessionAffinityTimeout,
				},
				&SvcLB{
					SvcID:  "ns/svc",
					IP:     "192.1.1.2",
					IsLBIP: true,
					Port: Port{
						Name:     "ssh",
						Protocol: corev1.ProtocolTCP,
						Port:     22,
					},
					TrafficPolicy:          ertype.TrafficPolicyCluster,
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: DefaultSessionAffinityTimeout,
				},
				&SvcLB{
					SvcID: "ns/svc",
					Port: Port{
						Name:     "ssh",
						Protocol: corev1.ProtocolTCP,
						NodePort: 33100,
					},
					TrafficPolicy:          ertype.TrafficPolicyCluster,
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: DefaultSessionAffinityTimeout,
				},
			},
			expErr: false,
		},
		{
			name:     "lb svc with proxyAll and without nodeport",
			proxyAll: true,
			svc: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "svc",
					Namespace: "ns",
				},
				Spec: corev1.ServiceSpec{
					Type:       corev1.ServiceTypeLoadBalancer,
					ClusterIP:  "10.10.1.1",
					ClusterIPs: []string{"10.10.1.1", "fe23::90"},
					Ports: []corev1.ServicePort{
						{
							Name:     "ssh",
							Protocol: corev1.ProtocolTCP,
							Port:     22,
						},
					},
					ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyCluster,
					SessionAffinity:       corev1.ServiceAffinityClientIP,
					InternalTrafficPolicy: &internalTPLocal,
				},
				Status: corev1.ServiceStatus{
					LoadBalancer: corev1.LoadBalancerStatus{
						Ingress: []corev1.LoadBalancerIngress{
							{
								IP: "192.1.1.1",
							},
							{
								IP: "192.1.1.2",
							},
						},
					},
				},
			},
			exp: []*SvcLB{
				&SvcLB{
					SvcID: "ns/svc",
					IP:    "10.10.1.1",
					Port: Port{
						Name:     "ssh",
						Protocol: corev1.ProtocolTCP,
						Port:     22,
					},
					TrafficPolicy:          ertype.TrafficPolicyLocal,
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: DefaultSessionAffinityTimeout,
				},
				&SvcLB{
					SvcID: "ns/svc",
					IP:    "192.1.1.1",
					Port: Port{
						Name:     "ssh",
						Protocol: corev1.ProtocolTCP,
						Port:     22,
					},
					IsLBIP:                 true,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: DefaultSessionAffinityTimeout,
				},
				&SvcLB{
					SvcID:  "ns/svc",
					IP:     "192.1.1.2",
					IsLBIP: true,
					Port: Port{
						Name:     "ssh",
						Protocol: corev1.ProtocolTCP,
						Port:     22,
					},
					TrafficPolicy:          ertype.TrafficPolicyCluster,
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: DefaultSessionAffinityTimeout,
				},
			},
			expErr: false,
		},
		{
			name:     "sessionaffinity = none",
			proxyAll: true,
			svc: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "svc",
					Namespace: "ns",
				},
				Spec: corev1.ServiceSpec{
					Type:       corev1.ServiceTypeLoadBalancer,
					ClusterIP:  "10.10.1.1",
					ClusterIPs: []string{"10.10.1.1", "fe23::90"},
					Ports: []corev1.ServicePort{
						{
							Name:     "ssh",
							Protocol: corev1.ProtocolTCP,
							Port:     22,
						},
					},
					ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyCluster,
					SessionAffinity:       corev1.ServiceAffinityNone,
					InternalTrafficPolicy: &internalTPLocal,
				},
				Status: corev1.ServiceStatus{
					LoadBalancer: corev1.LoadBalancerStatus{
						Ingress: []corev1.LoadBalancerIngress{
							{
								IP: "192.1.1.1",
							},
							{
								IP: "192.1.1.2",
							},
						},
					},
				},
			},
			exp: []*SvcLB{
				&SvcLB{
					SvcID: "ns/svc",
					IP:    "10.10.1.1",
					Port: Port{
						Name:     "ssh",
						Protocol: corev1.ProtocolTCP,
						Port:     22,
					},
					TrafficPolicy:   ertype.TrafficPolicyLocal,
					SessionAffinity: corev1.ServiceAffinityNone,
				},
				&SvcLB{
					SvcID:  "ns/svc",
					IP:     "192.1.1.1",
					IsLBIP: true,
					Port: Port{
						Name:     "ssh",
						Protocol: corev1.ProtocolTCP,
						Port:     22,
					},
					TrafficPolicy:   ertype.TrafficPolicyCluster,
					SessionAffinity: corev1.ServiceAffinityNone,
				},
				&SvcLB{
					SvcID:  "ns/svc",
					IP:     "192.1.1.2",
					IsLBIP: true,
					Port: Port{
						Name:     "ssh",
						Protocol: corev1.ProtocolTCP,
						Port:     22,
					},
					TrafficPolicy:   ertype.TrafficPolicyCluster,
					SessionAffinity: corev1.ServiceAffinityNone,
				},
			},
			expErr: false,
		},
		{
			name:     "sessionaffinity = clientIP with valid affinitytime",
			proxyAll: false,
			svc: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "svc",
					Namespace: "ns",
				},
				Spec: corev1.ServiceSpec{
					Type:       corev1.ServiceTypeLoadBalancer,
					ClusterIP:  "10.10.1.1",
					ClusterIPs: []string{"10.10.1.1", "fe23::90"},
					Ports: []corev1.ServicePort{
						{
							Name:     "ssh",
							Protocol: corev1.ProtocolTCP,
							Port:     22,
						},
					},
					ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyCluster,
					SessionAffinity:       corev1.ServiceAffinityClientIP,
					SessionAffinityConfig: &corev1.SessionAffinityConfig{
						ClientIP: &corev1.ClientIPConfig{
							TimeoutSeconds: &timeout,
						},
					},
					InternalTrafficPolicy: &internalTPLocal,
				},
				Status: corev1.ServiceStatus{
					LoadBalancer: corev1.LoadBalancerStatus{
						Ingress: []corev1.LoadBalancerIngress{
							{
								IP: "192.1.1.1",
							},
							{
								IP: "192.1.1.2",
							},
						},
					},
				},
			},
			exp: []*SvcLB{
				&SvcLB{
					SvcID: "ns/svc",
					IP:    "10.10.1.1",
					Port: Port{
						Name:     "ssh",
						Protocol: corev1.ProtocolTCP,
						Port:     22,
					},
					TrafficPolicy:          ertype.TrafficPolicyLocal,
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: int32(timeout),
				},
			},
			expErr: false,
		},
		{
			name:     "sessionaffinity = clientIP with invalid affinitytime",
			proxyAll: false,
			svc: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "svc",
					Namespace: "ns",
				},
				Spec: corev1.ServiceSpec{
					Type:       corev1.ServiceTypeLoadBalancer,
					ClusterIP:  "10.10.1.1",
					ClusterIPs: []string{"10.10.1.1", "fe23::90"},
					Ports: []corev1.ServicePort{
						{
							Name:     "ssh",
							Protocol: corev1.ProtocolTCP,
							Port:     22,
						},
					},
					ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyCluster,
					SessionAffinity:       corev1.ServiceAffinityClientIP,
					SessionAffinityConfig: &corev1.SessionAffinityConfig{
						ClientIP: &corev1.ClientIPConfig{
							TimeoutSeconds: &invalidTimeout,
						},
					},
					InternalTrafficPolicy: &internalTPLocal,
				},
				Status: corev1.ServiceStatus{
					LoadBalancer: corev1.LoadBalancerStatus{
						Ingress: []corev1.LoadBalancerIngress{
							{
								IP: "192.1.1.1",
							},
							{
								IP: "192.1.1.2",
							},
						},
					},
				},
			},
			exp:    nil,
			expErr: true,
		},
		{
			name:     "port protocol with sftp",
			proxyAll: false,
			svc: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "svc",
					Namespace: "ns",
				},
				Spec: corev1.ServiceSpec{
					Type:       corev1.ServiceTypeLoadBalancer,
					ClusterIP:  "10.10.1.1",
					ClusterIPs: []string{"10.10.1.1", "fe23::90"},
					Ports: []corev1.ServicePort{
						{
							Name:     "ssh",
							Protocol: corev1.ProtocolSCTP,
							Port:     22,
						},
					},
					ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyCluster,
					SessionAffinity:       corev1.ServiceAffinityClientIP,
					SessionAffinityConfig: &corev1.SessionAffinityConfig{
						ClientIP: &corev1.ClientIPConfig{
							TimeoutSeconds: &timeout,
						},
					},
					InternalTrafficPolicy: &internalTPLocal,
				},
				Status: corev1.ServiceStatus{
					LoadBalancer: corev1.LoadBalancerStatus{
						Ingress: []corev1.LoadBalancerIngress{
							{
								IP: "192.1.1.1",
							},
							{
								IP: "192.1.1.2",
							},
						},
					},
				},
			},
			exp:    nil,
			expErr: false,
		},
	}
	for _, c := range cases {
		res, err := ServiceToSvcLBs(c.svc, c.proxyAll)
		if (err != nil) != c.expErr {
			t.Errorf("test %s failed, exp err failed", c.name)
			continue
		}
		if len(res) != len(c.exp) {
			t.Errorf("test %s failed, exp is %v, real is %v", c.name, c.exp, res)
			continue
		}
		for i := range c.exp {
			real := res[c.exp[i].ID()]
			if *real != *c.exp[i] {
				t.Errorf("test %s failed, exp is %v, real is %v", c.name, c.exp[i], real)
			}
		}
	}
}
