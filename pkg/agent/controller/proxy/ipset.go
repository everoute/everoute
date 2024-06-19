package proxy

import (
	"context"
	"fmt"
	"sync"

	"github.com/gonetx/ipset"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	uerr "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	proxycache "github.com/everoute/everoute/pkg/agent/controller/proxy/cache"
)

type PortType string

var TCP = PortType(corev1.ProtocolTCP)
var UDP = PortType(corev1.ProtocolUDP)

type IPPort struct {
	ip       string
	protocol corev1.Protocol
	port     int32
}

func NewIPPort(ip string, pro corev1.Protocol, port int32) *IPPort {
	return &IPPort{
		ip:       ip,
		protocol: pro,
		port:     port,
	}
}

func (i IPPort) String() string {
	return fmt.Sprintf("%s,%s:%d", i.ip, i.protocol, i.port)
}

type IPSetCtrl struct {
	client.Client
	TCPSet ipset.IPSet
	UDPSet ipset.IPSet
	LBSet  ipset.IPSet

	npLock    sync.RWMutex
	nodePorts map[string]map[PortType]sets.Set[int32]
	lbLock    sync.RWMutex
	lbIPPorts map[string]sets.Set[IPPort]

	logPre string
}

var _ reconcile.Reconciler = &IPSetCtrl{}

func (p *IPSetCtrl) SetupWithManager(mgr ctrl.Manager) error {
	if p.TCPSet == nil || p.UDPSet == nil || p.LBSet == nil {
		return fmt.Errorf("ipset can't be nil")
	}

	p.nodePorts = make(map[string]map[PortType]sets.Set[int32])
	p.lbIPPorts = make(map[string]sets.Set[IPPort])
	p.logPre = "IPset controller"

	c, err := controller.New("proxy ipset conrtoller", mgr, controller.Options{
		Reconciler: p,
	})
	if err != nil {
		return nil
	}

	return c.Watch(source.Kind(mgr.GetCache(), &corev1.Service{}), &handler.EnqueueRequestForObject{}, predicate.Funcs{
		CreateFunc: p.predicateCreate,
		UpdateFunc: p.predicateUpdate,
	})
}

func (p *IPSetCtrl) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.Infof("%s, receive reconcile service %s", p.logPre, req.NamespacedName)
	svc := corev1.Service{}
	if err := p.Client.Get(ctx, req.NamespacedName, &svc); err != nil {
		if apierrors.IsNotFound(err) {
			if err := p.Delete(req.NamespacedName); err != nil {
				klog.Errorf("%s, failed to delete service %s, err: %s", p.logPre, req.NamespacedName, err)
				return ctrl.Result{}, err
			}
			klog.Infof("%s, success to delete service %s", p.logPre, req.NamespacedName)
			return ctrl.Result{}, nil
		}
		klog.Errorf("%s, failed to get service %s, err: %s", p.logPre, req.NamespacedName, err)
		return ctrl.Result{}, err
	}

	if err := p.CreateOrUpdate(&svc); err != nil {
		klog.Errorf("%s, failed to create or update service %v, err: %s", p.logPre, svc, err)
		return ctrl.Result{}, err
	}
	klog.Infof("%s, success to create or update service %s", p.logPre, req.NamespacedName)
	return ctrl.Result{}, nil
}

func (p *IPSetCtrl) Delete(svc types.NamespacedName) error {
	var errs []error
	svcID := proxycache.GenSvcID(svc.Namespace, svc.Name)
	if p.isNPExistWithLock(svcID) {
		if err := p.deleteNPSvc(svcID); err != nil {
			klog.Errorf("%s, failed to delete service %s node ports, err: %s", p.logPre, svc, err)
			errs = append(errs, err)
		}
	}

	if p.isLBExistWithLock(svcID) {
		if err := p.deleteLBSvc(svcID); err != nil {
			klog.Errorf("%s, failed to delete service %s load balancer ip ports, err: %s", p.logPre, svc, err)
			errs = append(errs, err)
		}
	}

	return uerr.NewAggregate(errs)
}

func (p *IPSetCtrl) CreateOrUpdate(svc *corev1.Service) error {
	var errs []error
	svcID := proxycache.GenSvcID(svc.GetNamespace(), svc.GetName())
	oldIsNP := p.isNPExistWithLock(svcID)
	oldIsLB := p.isLBExistWithLock(svcID)
	newIsNP := isNodePortSvc(svc)
	newIsLB := isLbSvc(svc)

	if newIsNP {
		if err := p.createOrUpdateNPSvc(svc); err != nil {
			klog.Errorf("%s, failed to create or update service %s node ports, err: %s", p.logPre, svcID, err)
			errs = append(errs, err)
		}
	} else {
		if oldIsNP {
			if err := p.deleteNPSvc(svcID); err != nil {
				klog.Errorf("%s, failed to delete service %s node ports, err: %s", p.logPre, svcID, err)
				errs = append(errs, err)
			}
		}
	}

	if newIsLB {
		if err := p.createOrUpdateLBSvc(svc); err != nil {
			klog.Errorf("%s, failed to create or update service %s loadbalancer ip ports, err: %s", p.logPre, svcID, err)
			errs = append(errs, err)
		}
	} else {
		if oldIsLB {
			if err := p.deleteLBSvc(svcID); err != nil {
				klog.Errorf("%s, failed to delete service %s loadbalancer ip ports, err: %s", p.logPre, svcID, err)
				errs = append(errs, err)
			}
		}
	}
	return uerr.NewAggregate(errs)
}

func (p *IPSetCtrl) isNPExistWithLock(svcID string) bool {
	p.npLock.RLock()
	defer p.npLock.RUnlock()

	_, ok := p.nodePorts[svcID]
	return ok
}

func (p *IPSetCtrl) isLBExistWithLock(svcID string) bool {
	p.lbLock.RLock()
	defer p.lbLock.RUnlock()

	_, ok := p.lbIPPorts[svcID]
	return ok
}

func (p *IPSetCtrl) deleteNPSvc(svcID string) error {
	p.npLock.Lock()
	defer p.npLock.Unlock()
	var errs []error

	if err := p.deleteNPSvcPort(svcID, TCP); err != nil {
		errs = append(errs, err)
	}

	if err := p.deleteNPSvcPort(svcID, UDP); err != nil {
		errs = append(errs, err)
	}

	if p.nodePorts[svcID] == nil || len(p.nodePorts[svcID]) == 0 {
		delete(p.nodePorts, svcID)
	}

	return uerr.NewAggregate(errs)
}

func (p *IPSetCtrl) deleteNPSvcPort(svcID string, portType PortType) error {
	if p.nodePorts[svcID] == nil || len(p.nodePorts[svcID]) == 0 {
		return nil
	}
	var errs []error

	if p.nodePorts[svcID][portType] != nil && p.nodePorts[svcID][portType].Len() > 0 {
		ports := p.nodePorts[svcID][portType].UnsortedList()
		for _, port := range ports {
			if err := p.deletePortFromIPSet(svcID, port, portType); err != nil {
				errs = append(errs, err)
				continue
			}
			p.nodePorts[svcID][portType].Delete(port)
		}
	}
	if p.nodePorts[svcID][portType] == nil || p.nodePorts[svcID][portType].Len() == 0 {
		delete(p.nodePorts[svcID], portType)
	}

	return uerr.NewAggregate(errs)
}

func (p *IPSetCtrl) createOrUpdateNPSvc(svc *corev1.Service) error {
	p.npLock.Lock()
	defer p.npLock.Unlock()
	var errs []error
	svcID := proxycache.GenSvcID(svc.GetNamespace(), svc.GetName())
	for _, portType := range []PortType{TCP, UDP} {
		pro := corev1.Protocol(portType)
		newPortSet := getNodePortsByProtocol(svc, pro)
		oldPortSet := p.getPortsByPortType(svcID, portType)
		delPorts := oldPortSet.Difference(newPortSet).UnsortedList()
		addPorts := newPortSet.Difference(oldPortSet).UnsortedList()
		if len(addPorts) > 0 {
			if p.nodePorts[svcID] == nil {
				p.nodePorts[svcID] = make(map[PortType]sets.Set[int32])
			}
			if p.nodePorts[svcID][portType] == nil {
				p.nodePorts[svcID][portType] = sets.New[int32]()
			}
			for _, port := range addPorts {
				if err := p.addPortToIPSet(svcID, port, portType); err != nil {
					errs = append(errs, err)
					continue
				}
				p.nodePorts[svcID][portType].Insert(port)
			}
		}
		for _, port := range delPorts {
			if err := p.deletePortFromIPSet(svcID, port, portType); err != nil {
				errs = append(errs, err)
				continue
			}
			p.nodePorts[svcID][portType].Delete(port)
		}
	}

	return uerr.NewAggregate(errs)
}

func (p *IPSetCtrl) deletePortFromIPSet(svcID string, port int32, portType PortType) error {
	if p.isPortInOtherSvc(svcID, port, portType) {
		return nil
	}
	ipSet := p.getIPSetByPortType(portType)
	portStr := fmt.Sprintf("%d", port)
	if err := ipSet.Del(portStr); err != nil {
		klog.Errorf("%s, failed to del service %s port %d from ipset %s, err: %s", p.logPre, svcID, port, ipSet.Name(), err)
		return err
	}
	return nil
}

func (p *IPSetCtrl) addPortToIPSet(svcID string, port int32, portType PortType) error {
	ipSet := p.getIPSetByPortType(portType)
	portStr := fmt.Sprintf("%d", port)
	if err := ipSet.Add(portStr, ipset.CommentContent(svcID)); err != nil {
		klog.Errorf("%s, failed to add service %s port %d to ipset %s, err: %s", p.logPre, svcID, port, ipSet.Name(), err)
		return err
	}
	return nil
}

func (p *IPSetCtrl) isPortInOtherSvc(thisSvc string, port int32, portType PortType) bool {
	for svcID := range p.nodePorts {
		if svcID == thisSvc {
			continue
		}
		if p.nodePorts[svcID] == nil || p.nodePorts[svcID][portType] == nil {
			continue
		}
		if p.nodePorts[svcID][portType].Has(port) {
			return true
		}
	}
	return false
}

func (p *IPSetCtrl) getIPSetByPortType(portType PortType) ipset.IPSet {
	if portType == TCP {
		return p.TCPSet
	}
	return p.UDPSet
}

func (p *IPSetCtrl) getPortsByPortType(svcID string, portType PortType) sets.Set[int32] {
	if _, ok := p.nodePorts[svcID]; !ok {
		return sets.New[int32]()
	}
	if p.nodePorts[svcID][portType] == nil {
		return sets.New[int32]()
	}

	return p.nodePorts[svcID][portType]
}

func (p *IPSetCtrl) deleteLBSvc(svcID string) error {
	p.lbLock.Lock()
	defer p.lbLock.Unlock()

	if p.lbIPPorts[svcID] == nil {
		delete(p.lbIPPorts, svcID)
		return nil
	}

	var errs []error
	ipPorts := p.lbIPPorts[svcID].UnsortedList()
	for i := range ipPorts {
		if err := p.deleteIPPortFromIPSet(svcID, ipPorts[i]); err != nil {
			errs = append(errs, err)
			continue
		}
		p.lbIPPorts[svcID].Delete(ipPorts[i])
	}

	if p.lbIPPorts[svcID].Len() == 0 {
		delete(p.lbIPPorts, svcID)
	}

	return uerr.NewAggregate(errs)
}

func (p *IPSetCtrl) createOrUpdateLBSvc(svc *corev1.Service) error {
	p.lbLock.Lock()
	defer p.lbLock.Unlock()

	var errs []error
	svcID := proxycache.GenSvcID(svc.GetNamespace(), svc.GetName())
	newLBIPPortSet := getLBIPPorts(svc)
	oldLBIPPortSet := p.lbIPPorts[svcID]
	if oldLBIPPortSet == nil {
		oldLBIPPortSet = sets.New[IPPort]()
	}

	addIPPorts := newLBIPPortSet.Difference(oldLBIPPortSet).UnsortedList()
	delIPPorts := oldLBIPPortSet.Difference(newLBIPPortSet).UnsortedList()
	if len(addIPPorts) > 0 {
		if p.lbIPPorts[svcID] == nil {
			p.lbIPPorts[svcID] = sets.New[IPPort]()
		}
	}
	for i := range addIPPorts {
		if err := p.LBSet.Add(addIPPorts[i].String(), ipset.CommentContent(svcID)); err != nil {
			klog.Errorf("%s, failed to add lb service %s ipport %s to ipset %s, err: %s", p.logPre, svcID, addIPPorts[i], p.LBSet.Name(), err)
			errs = append(errs, err)
			continue
		}
		p.lbIPPorts[svcID].Insert(addIPPorts[i])
	}
	for i := range delIPPorts {
		if err := p.deleteIPPortFromIPSet(svcID, delIPPorts[i]); err != nil {
			klog.Errorf("%s, failed to delete service %s loadbalancer ipport %s from ipset %s, err: %s", p.logPre, svcID, delIPPorts[i], p.LBSet.Name(), err)
			errs = append(errs, err)
			continue
		}
		p.lbIPPorts[svcID].Delete(delIPPorts[i])
	}

	if p.lbIPPorts[svcID] == nil || p.lbIPPorts[svcID].Len() == 0 {
		delete(p.lbIPPorts, svcID)
	}
	return uerr.NewAggregate(errs)
}

func (p *IPSetCtrl) deleteIPPortFromIPSet(svcID string, ipPort IPPort) error {
	if p.isIPPortInOtherSvc(svcID, ipPort) {
		return nil
	}

	err := p.LBSet.Del(ipPort.String(), ipset.CommentContent(svcID))
	if err != nil {
		klog.Errorf("%s, failed to delete service %s loadbalancer ip port %s from ipset %s, err: %s", p.logPre, svcID, ipPort, p.LBSet.Name(), err)
	}
	return err
}

func (p *IPSetCtrl) isIPPortInOtherSvc(thisSvc string, ipPort IPPort) bool {
	for svcID := range p.lbIPPorts {
		if svcID == thisSvc {
			continue
		}
		if p.lbIPPorts[svcID] == nil {
			continue
		}

		if p.lbIPPorts[svcID].Has(ipPort) {
			return true
		}
	}

	return false
}

func (*IPSetCtrl) predicateCreate(e event.CreateEvent) bool {
	o, ok := e.Object.(*corev1.Service)
	if !ok {
		klog.Errorf("proxy ipset controller, create event transform to service failed, event: %v", e)
		return false
	}
	if o.Spec.Type == corev1.ServiceTypeLoadBalancer || o.Spec.Type == corev1.ServiceTypeNodePort {
		return true
	}

	return false
}

func (*IPSetCtrl) predicateUpdate(e event.UpdateEvent) bool {
	oldO, ok := e.ObjectOld.(*corev1.Service)
	if !ok {
		klog.Errorf("proxy ipset controller, update event old object transform to service failed, event: %v", e.ObjectOld)
		return false
	}
	newO, ok := e.ObjectNew.(*corev1.Service)
	if !ok {
		klog.Errorf("proxy ipset controller, update event new object transform to service failed, event: %v", e.ObjectNew)
		return false
	}
	if oldO.Spec.Type == corev1.ServiceTypeLoadBalancer || oldO.Spec.Type == corev1.ServiceTypeNodePort {
		return true
	}
	if newO.Spec.Type == corev1.ServiceTypeLoadBalancer || newO.Spec.Type == corev1.ServiceTypeNodePort {
		return true
	}

	return false
}
