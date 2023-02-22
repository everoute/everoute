package cache

import (
	"net"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
	utilnet "k8s.io/utils/net"
)

// BaseSvc store a service base info
type BaseSvc struct {
	// SvcID is unique identifier of BaseSvc, it should be set svcNamespace/svcName
	SvcID   string
	SvcType corev1.ServiceType

	ClusterIPs []string
	// Ports the key is portname
	Ports map[string]*Port

	// ExternalTrafficPolicy ClusterIP doesn't use it
	ExternalTrafficPolicy TrafficPolicyType
	InternalTrafficPolicy TrafficPolicyType

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

// TrafficPolicyType is service internal or external traffic policy
type TrafficPolicyType string

const (
	TrafficPolicyCluster TrafficPolicyType = "Cluster"
	TrafficPOlicyLocal   TrafficPolicyType = "Local"

	DefaultSessionAffinityTimeout int32 = 10800
)

func NewBaseSvcCache() cache.Indexer {
	return cache.NewIndexer(baseSvcKeyFunc, cache.Indexers{})
}

func GenSvcID(svcNS string, svcName string) string {
	return svcNS + "/" + svcName
}

func ServiceToBaseSvc(svc *corev1.Service) *BaseSvc {
	if svc == nil {
		return nil
	}

	baseSvc := &BaseSvc{
		SvcID:                 GenSvcID(svc.Namespace, svc.Name),
		SvcType:               svc.Spec.Type,
		ClusterIPs:            GetClusterIPs(svc.Spec),
		ExternalTrafficPolicy: TrafficPolicyType(svc.Spec.ExternalTrafficPolicy),
		// todo upgrade k8s.io/api version
		InternalTrafficPolicy: TrafficPolicyCluster,
		SessionAffinity:       svc.Spec.SessionAffinity,
		Ports:                 make(map[string]*Port),
	}

	if baseSvc.SessionAffinity == corev1.ServiceAffinityClientIP {
		if svc.Spec.SessionAffinityConfig != nil && svc.Spec.SessionAffinityConfig.ClientIP != nil && svc.Spec.SessionAffinityConfig.ClientIP.TimeoutSeconds != nil {
			timeout := *svc.Spec.SessionAffinityConfig.ClientIP.TimeoutSeconds
			if timeout <= 0 {
				klog.Errorf("Invalid service SessionAffinityTimeout %d for service %s", timeout, baseSvc.SvcID)
				return nil
			}
			baseSvc.SessionAffinityTimeout = timeout
		} else {
			baseSvc.SessionAffinityTimeout = DefaultSessionAffinityTimeout
		}
	}

	for i := range svc.Spec.Ports {
		svcPort := svc.Spec.Ports[i]
		p := servicePortToPort(&svcPort)
		if p != nil {
			baseSvc.Ports[p.Name] = p
		}
	}

	return baseSvc
}

func GetClusterIPs(spec corev1.ServiceSpec) []string {
	res := make([]string, 0)
	// only support ipv4
	if utilnet.IsIPv4(net.ParseIP(spec.ClusterIP)) {
		res = append(res, spec.ClusterIP)
	}
	return res
}

func (b *BaseSvc) DeepCopy() *BaseSvc {
	res := &BaseSvc{
		SvcID:                  b.SvcID,
		SvcType:                b.SvcType,
		ClusterIPs:             make([]string, 0),
		Ports:                  make(map[string]*Port),
		ExternalTrafficPolicy:  b.ExternalTrafficPolicy,
		InternalTrafficPolicy:  b.InternalTrafficPolicy,
		SessionAffinity:        b.SessionAffinity,
		SessionAffinityTimeout: b.SessionAffinityTimeout,
	}
	res.ClusterIPs = append(res.ClusterIPs, b.ClusterIPs...)

	for pName := range b.Ports {
		curP := *b.Ports[pName]
		res.Ports[pName] = &curP
	}

	return res
}

func (b *BaseSvc) ListPorts() []*Port {
	var res []*Port
	for k := range b.Ports {
		if b.Ports[k] != nil {
			res = append(res, b.Ports[k])
		}
	}
	return res
}

func (b *BaseSvc) DiffClusterIPs(new *BaseSvc) (add, del []string) {
	newSets := sets.NewString(new.ClusterIPs...)
	oldSets := sets.NewString(b.ClusterIPs...)
	add = newSets.Difference(oldSets).List()
	del = oldSets.Difference(newSets).List()

	return
}

func (b *BaseSvc) ChangeAffinityMode(new *BaseSvc) bool {
	return b.SessionAffinity != new.SessionAffinity
}

func (b *BaseSvc) ChangeAffinityTimeout(new *BaseSvc) bool {
	return b.SessionAffinityTimeout != new.SessionAffinityTimeout
}

func (b *BaseSvc) DiffPorts(new *BaseSvc) (add, update, del []*Port) {
	for oldName := range b.Ports {
		if v, ok := new.Ports[oldName]; !ok || v == nil {
			del = append(del, b.Ports[oldName])
		} else if b.Ports[oldName].validUpdate(new.Ports[oldName]) {
			update = append(update, new.Ports[oldName])
		}
	}

	for newName := range new.Ports {
		if v, ok := b.Ports[newName]; !ok || v == nil {
			add = append(add, new.Ports[newName])
		}
	}

	return
}

func (p *Port) validUpdate(new *Port) bool {
	if p.Port != new.Port {
		return true
	}
	if p.Protocol != new.Protocol {
		return true
	}
	return false
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

func baseSvcKeyFunc(obj interface{}) (string, error) {
	return obj.(*BaseSvc).SvcID, nil
}
