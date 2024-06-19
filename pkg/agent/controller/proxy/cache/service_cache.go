package cache

import (
	"fmt"
	"net"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	ertype "github.com/everoute/everoute/pkg/types"
)

// SvcLB store a service info for each ip and port
type SvcLB struct {
	// SvcID is unique identifier of BaseSvc, it should be set svcNamespace/svcName
	SvcID         string
	IP            string
	Port          Port
	TrafficPolicy ertype.TrafficPolicyType

	SessionAffinity corev1.ServiceAffinity
	// SessionAffinityTimeout，the unit is seconds
	SessionAffinityTimeout int32
}

// Port is service port info
type Port struct {
	// Name represents the associated name with this Port number.
	Name string
	// Protocol for port. Must be UDP, TCP  TODO not icmp webhook
	Protocol corev1.Protocol
	// Port represents the ClusterIP Service Port number.
	Port int32
	// Nodeport represents the NodePort Service NodePort number.
	NodePort int32
}

const (
	DefaultSessionAffinityTimeout int32 = 10800
)

func NewSvcLBCache() cache.Indexer {
	return cache.NewIndexer(svcLBKeyFunc,
		cache.Indexers{
			SvcIDIndex:   svcIDIndexFunc,
			SvcPortIndex: svcPortIndexFuncForSvcLB,
		})
}

func ServiceToSvcLBs(svc *corev1.Service, proxyAll bool) (map[string]*SvcLB, error) {
	if svc == nil {
		return nil, fmt.Errorf("service can't be nil")
	}

	svcID := GenSvcID(svc.Namespace, svc.Name)

	// traffic policy
	internalTrafficPolicy := ertype.TrafficPolicyCluster
	if svc.Spec.InternalTrafficPolicy != nil {
		internalTrafficPolicy = ertype.TrafficPolicyType(*svc.Spec.InternalTrafficPolicy)
	}

	// session affinity config
	sessionAffinity := svc.Spec.SessionAffinity
	var sessionAffinityTimeout int32
	if sessionAffinity == corev1.ServiceAffinityClientIP {
		if svc.Spec.SessionAffinityConfig != nil && svc.Spec.SessionAffinityConfig.ClientIP != nil && svc.Spec.SessionAffinityConfig.ClientIP.TimeoutSeconds != nil {
			timeout := *svc.Spec.SessionAffinityConfig.ClientIP.TimeoutSeconds
			if timeout <= 0 {
				klog.Errorf("Invalid service SessionAffinityTimeout %d for service %s", timeout, svcID)
				return nil, fmt.Errorf("invalid SessionAffinityTimeout %d", timeout)
			}
			sessionAffinityTimeout = timeout
		} else {
			sessionAffinityTimeout = DefaultSessionAffinityTimeout
		}
	}

	clusterIPs := GetClusterIPs(svc.Spec)
	lbIPs := []string{}
	if proxyAll {
		lbIPs = GetLBIPs(svc.Status)
	}
	res := make(map[string]*SvcLB)
	for i := range svc.Spec.Ports {
		svcPort := svc.Spec.Ports[i]
		p := servicePortToPort(&svcPort)
		if p == nil {
			continue
		}
		if proxyAll && p.NodePort != 0 {
			port := *p
			port.Port = 0
			svcLB := &SvcLB{
				SvcID:                  svcID,
				Port:                   port,
				TrafficPolicy:          ertype.TrafficPolicyType(svc.Spec.ExternalTrafficPolicy),
				SessionAffinity:        sessionAffinity,
				SessionAffinityTimeout: sessionAffinityTimeout,
			}
			res[svcLB.ID()] = svcLB
		}
		p.NodePort = 0
		for _, ip := range clusterIPs {
			svcLB := &SvcLB{
				SvcID:                  svcID,
				IP:                     ip,
				Port:                   *p,
				TrafficPolicy:          internalTrafficPolicy,
				SessionAffinity:        sessionAffinity,
				SessionAffinityTimeout: sessionAffinityTimeout,
			}
			res[svcLB.ID()] = svcLB
		}
		for _, ip := range lbIPs {
			svcLB := &SvcLB{
				SvcID:                  svcID,
				IP:                     ip,
				Port:                   *p,
				TrafficPolicy:          ertype.TrafficPolicyType(svc.Spec.ExternalTrafficPolicy),
				SessionAffinity:        sessionAffinity,
				SessionAffinityTimeout: sessionAffinityTimeout,
			}
			res[svcLB.ID()] = svcLB
		}
	}

	return res, nil
}

func GetClusterIPs(spec corev1.ServiceSpec) []string {
	res := make([]string, 0)
	// only support ipv4
	if net.ParseIP(spec.ClusterIP).To4() != nil {
		res = append(res, spec.ClusterIP)
	}
	return res
}

func GetLBIPs(status corev1.ServiceStatus) []string {
	res := make([]string, 0)

	for i := range status.LoadBalancer.Ingress {
		ip := status.LoadBalancer.Ingress[i].IP
		// only support ipv4
		if net.ParseIP(ip).To4() != nil {
			res = append(res, ip)
		}
	}
	return res
}

func (s *SvcLB) ID() string {
	return s.SvcID + "/" + s.IP + "/" + s.Port.Name
}

func (s *SvcLB) Valid() bool {
	if s.Port.Protocol != corev1.ProtocolTCP && s.Port.Protocol != corev1.ProtocolUDP {
		return false
	}
	if s.IP == "" && s.Port.NodePort == 0 {
		return false
	}
	if s.IP != "" && s.Port.Port == 0 {
		return false
	}
	return true
}

func (s *SvcLB) DeepCopy() *SvcLB {
	res := &SvcLB{}
	*res = *s
	return res
}

func (s *SvcLB) ResetSessionAffinityConfig() {
	s.SessionAffinity = corev1.ServiceAffinityNone
	s.SessionAffinityTimeout = 0
}

func servicePortToPort(svcPort *corev1.ServicePort) *Port {
	if svcPort == nil {
		return nil
	}
	if svcPort.Protocol != corev1.ProtocolTCP && svcPort.Protocol != corev1.ProtocolUDP {
		klog.Infof("Unsupport service port protocol %s, skip", string(svcPort.Protocol))
		return nil
	}
	return &Port{
		Name:     svcPort.Name,
		Protocol: svcPort.Protocol,
		Port:     svcPort.Port,
		NodePort: svcPort.NodePort,
	}
}

func svcLBKeyFunc(obj interface{}) (string, error) {
	o := obj.(*SvcLB)
	return o.ID(), nil
}

func svcIDIndexFunc(obj interface{}) ([]string, error) {
	o := obj.(*SvcLB)
	return []string{o.SvcID}, nil
}

func svcPortIndexFuncForSvcLB(obj interface{}) ([]string, error) {
	o := obj.(*SvcLB)
	return []string{o.SvcID + "/" + o.Port.Name}, nil
}
