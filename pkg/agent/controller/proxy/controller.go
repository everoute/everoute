package proxy

import (
	"context"
	"fmt"
	"sync"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	proxycache "github.com/everoute/everoute/pkg/agent/controller/proxy/cache"
	"github.com/everoute/everoute/pkg/agent/datapath"
	everoutesvc "github.com/everoute/everoute/pkg/apis/service/v1alpha1"
)

// Reconcile watch Service related resource and implement Service
type Reconcile struct {
	client.Client
	Scheme *runtime.Scheme
	DpMgr  *datapath.DpManager

	baseSvcCache cache.Indexer
	svcPortCache cache.Indexer
	backendCache cache.Indexer
}

// ReconcileService receive Service from work queue
func (r *Reconcile) ReconcileService(req ctrl.Request) (ctrl.Result, error) {
	klog.Infof("Receive Service %+v reconcile", req.NamespacedName)
	var svc corev1.Service
	ctx := context.Background()
	err := r.Get(ctx, req.NamespacedName, &svc)
	if client.IgnoreNotFound(err) != nil {
		klog.Errorf("Failed to get service: %v, err: %s", req.NamespacedName, err)
		return ctrl.Result{}, err
	}

	if apierrors.IsNotFound(err) {
		if err := r.deleteService(ctx, req.NamespacedName); err != nil {
			klog.Errorf("Failed to delete service: %v, err: %s", req.NamespacedName, err)
			return ctrl.Result{}, err
		}
		klog.Infof("Success delete service: %v", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	if len(proxycache.GetClusterIPs(svc.Spec)) == 0 {
		klog.Infof("Receive a update or add event for headless or externalName service: %v, delete it", svc)
		if err := r.deleteService(ctx, req.NamespacedName); err != nil {
			klog.Errorf("Failed to process headless or externalName service: %v, err: %s", req.NamespacedName, err)
			return ctrl.Result{}, err
		}
		klog.Infof("Success process the headless or externalName service: %v", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	if err := r.updateService(ctx, &svc); err != nil {
		klog.Errorf("Failed to add or update service: %+v, err: %s", svc, err)
		return ctrl.Result{}, err
	}
	klog.Infof("Success add or update service: %v", req.NamespacedName)
	return ctrl.Result{}, nil
}

// ReconcileSvcPort receive servicePort from work queue
func (r *Reconcile) ReconcileServicePort(req ctrl.Request) (ctrl.Result, error) {
	klog.Infof("Receive ServicePort %+v reconcile", req.NamespacedName)
	ctx := context.Background()
	svcPort := everoutesvc.ServicePort{}
	err := r.Client.Get(ctx, req.NamespacedName, &svcPort)
	if client.IgnoreNotFound(err) != nil {
		klog.Errorf("Failed to get ServicePort %+v, err: %s", req.NamespacedName, err)
		return ctrl.Result{}, err
	}

	if apierrors.IsNotFound(err) {
		if err := r.deleteServicePort(ctx, req.NamespacedName); err != nil {
			klog.Errorf("Failed to delete ServicePort %+v, err: %s", req.NamespacedName, err)
			return ctrl.Result{}, err
		}
		klog.Infof("Success delete ServicePort %+v", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	if err := r.updateServicePort(ctx, &svcPort); err != nil {
		klog.Errorf("Failed to add or update servicePort %+v, err: %s", svcPort, err)
		return ctrl.Result{}, err
	}
	klog.Infof("Success add or update ServicePort %+v", req.NamespacedName)
	return ctrl.Result{}, nil
}

// SetupWithManager add service controller and servicePort controller to mgr
func (r *Reconcile) SetupWithManager(mgr ctrl.Manager) error {
	if mgr == nil {
		return fmt.Errorf("can't setup with nil manager")
	}

	if r.baseSvcCache == nil {
		r.baseSvcCache = proxycache.NewBaseSvcCache()
	}

	if r.svcPortCache == nil {
		r.svcPortCache = proxycache.NewSvcPortCache()
	}

	if r.backendCache == nil {
		r.backendCache = proxycache.NewBackendCache()
	}

	svcController, err := controller.New("service controller", mgr, controller.Options{
		Reconciler: reconcile.Func(r.ReconcileService),
	})
	if err != nil {
		return err
	}

	if err := svcController.Watch(&source.Kind{Type: &corev1.Service{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return err
	}

	svcPortController, err := controller.New("servicePort controller", mgr, controller.Options{
		Reconciler: reconcile.Func(r.ReconcileServicePort),
	})
	if err != nil {
		return err
	}

	if err := svcPortController.Watch(&source.Kind{Type: &everoutesvc.ServicePort{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return err
	}

	return nil
}

func (r *Reconcile) updateService(ctx context.Context, newService *corev1.Service) error {
	new := proxycache.ServiceToBaseSvc(newService)
	if new == nil {
		klog.Errorf("Failed to transfer service %+v to baseSvc cache", newService)
		return fmt.Errorf("failed to transfer service %+v to baseSvc cache", newService)
	}

	baseSvcID := proxycache.GenSvcID(newService.Namespace, newService.Name)
	oldObj, oldExists, err := r.baseSvcCache.GetByKey(baseSvcID)
	if err != nil {
		klog.Errorf("Failed to get baseSvcCache for service: %s, err: %s", baseSvcID, err)
		return err
	}

	if !oldExists || oldObj == nil {
		if err := r.processServiceAdd(ctx, new); err != nil {
			klog.Errorf("Failed to add service: %+v, err: %s", new, err)
			return err
		}
		return nil
	}

	old := oldObj.(*proxycache.BaseSvc).DeepCopy()
	if err := r.processServiceUpdate(ctx, new, old); err != nil {
		klog.Errorf("Failed to update service: %+v, err: %s", new, err)
		return err
	}
	return nil
}

func (r *Reconcile) processServiceAdd(ctx context.Context, new *proxycache.BaseSvc) error {
	if new == nil {
		return nil
	}
	for _, ip := range new.ClusterIPs {
		if err := r.addClusterIP(ip, new); err != nil {
			klog.Errorf("Failed to add cluster ip %s for service %s, err: %s", ip, new.SvcID, err)
			return err
		}
	}

	if err := r.baseSvcCache.Add(new); err != nil {
		klog.Errorf("Failed to add service %+v to baseSvcCache", *new)
		return err
	}

	return nil
}

func (r *Reconcile) processServiceUpdate(ctx context.Context, new *proxycache.BaseSvc, old *proxycache.BaseSvc) error {
	if new == nil || old == nil {
		klog.Errorf("Missing service old or new info, old is %+v, new is %+v", old, new)
		return fmt.Errorf("missing service old or new info")
	}

	// cluster ips
	addIPs, delIPs := old.DiffClusterIPs(new)
	for _, ip := range addIPs {
		if err := r.addClusterIP(ip, old); err != nil {
			klog.Errorf("Failed to add cluster ip %s for service %s, err: %s", ip, new.SvcID, err)
			return err
		}
	}
	for _, ip := range delIPs {
		if err := r.delClusterIP(ip, old); err != nil {
			klog.Errorf("Failed to delete cluster ip %s for service %s, err: %s", ip, new.SvcID, err)
			return err
		}
	}
	old.ClusterIPs = new.ClusterIPs
	if err := r.baseSvcCache.Update(old.DeepCopy()); err != nil {
		klog.Errorf("Failed to update service %s clusterIPs to baseSvcCache, err: %s", old.SvcID, err)
		return err
	}

	klog.Infof("Success process service %s clusterips update", new.SvcID)

	// ports
	if err := r.processUpdatePortOfService(new, old); err != nil {
		klog.Errorf("Failed to process service %+v ports update, err: %s", *new, err)
		return err
	}
	klog.Infof("Success process service %s ports update", new.SvcID)

	// session affinity
	if err := r.processUpdateSessionAffinityOfService(new, old); err != nil {
		klog.Errorf("Failed to process service %+v session affinity config update, err: %s", *new, err)
		return err
	}
	klog.Infof("Success process service %s session affinity config update", new.SvcID)
	return nil
}

func (r *Reconcile) deleteService(ctx context.Context, svcNamespacedName types.NamespacedName) error {
	baseSvcID := proxycache.GenSvcID(svcNamespacedName.Namespace, svcNamespacedName.Name)

	dpNatBrs := r.DpMgr.GetNatBridges()
	for i := range dpNatBrs {
		if err := dpNatBrs[i].DelService(baseSvcID); err != nil {
			klog.Errorf("failed to delete service %s in dp, err: %s", svcNamespacedName, err)
			return err
		}
	}

	oldObj, exists, err := r.baseSvcCache.GetByKey(baseSvcID)
	if err != nil {
		klog.Errorf("Failed to get baseSvcCache for service: %v, err: %s", svcNamespacedName, err)
		return err
	}
	if !exists || oldObj == nil {
		klog.Infof("The service %v has been delete in baseSvcCache", svcNamespacedName)
		return nil
	}
	old := oldObj.(*proxycache.BaseSvc)
	if err := r.baseSvcCache.Delete(old); err != nil {
		klog.Errorf("Failed to delete service %s from baseSvcCache, err: %s", old.SvcID, err)
		return err
	}
	return nil
}

func (r *Reconcile) addClusterIP(ip string, baseSvc *proxycache.BaseSvc) error {
	if baseSvc == nil {
		return fmt.Errorf("missing service base info for add cluster IP: %s", ip)
	}
	dpNatBrs := r.DpMgr.GetNatBridges()
	for i := range dpNatBrs {
		dpNatBr := dpNatBrs[i]
		var ports []*proxycache.Port
		for pname := range baseSvc.Ports {
			if baseSvc.Ports[pname] != nil {
				ports = append(ports, baseSvc.Ports[pname])
			}
		}
		if err := dpNatBr.AddLBIP(baseSvc.SvcID, ip, ports, baseSvc.SessionAffinityTimeout); err != nil {
			klog.Errorf("Failed to add service clusterIP related flow, clusterIP: %s, err: %s", ip, err)
			return err
		}
	}
	return nil
}

func (r *Reconcile) delClusterIP(ip string, svcBase *proxycache.BaseSvc) error {
	if svcBase == nil {
		return fmt.Errorf("missing service base info for delete cluster IP: %s", ip)
	}
	dpNatBrs := r.DpMgr.GetNatBridges()
	for i := range dpNatBrs {
		dpNatBr := dpNatBrs[i]
		if err := dpNatBr.DelLBIP(svcBase.SvcID, ip); err != nil {
			klog.Errorf("Failed to del cluster ip %s for service %s, err: %s", ip, svcBase.SvcID, err)
			return err
		}
	}
	return nil
}

func (r *Reconcile) processUpdatePortOfService(new *proxycache.BaseSvc, old *proxycache.BaseSvc) error {
	if new == nil || old == nil {
		klog.Errorf("Missing service old or new info, old is %+v, new is %+v", old, new)
		return fmt.Errorf("missing service old or new info")
	}

	dpNatBrs := r.DpMgr.GetNatBridges()
	addPorts, updPorts, delPorts := old.DiffPorts(new)

	for i := range addPorts {
		port := addPorts[i]
		if port == nil {
			continue
		}
		for j := range dpNatBrs {
			if err := dpNatBrs[j].AddLBPort(old.SvcID, port, old.ClusterIPs, old.SessionAffinityTimeout); err != nil {
				klog.Errorf("Failed to add port %+v for service %+v, err: %s", *port, *old, err)
				return err
			}
		}
	}
	for i := range delPorts {
		port := delPorts[i]
		if port == nil {
			continue
		}
		for j := range dpNatBrs {
			if err := dpNatBrs[j].DelLBPort(old.SvcID, port.Name); err != nil {
				klog.Errorf("Failed to delete lb flow and group for service %s port %+v, err: %s", old.SvcID, *port, err)
				return err
			}
		}
	}
	for i := range updPorts {
		port := updPorts[i]
		if port == nil {
			continue
		}
		for j := range dpNatBrs {
			if err := dpNatBrs[j].UpdateLBPort(old.SvcID, port, old.ClusterIPs, old.SessionAffinityTimeout); err != nil {
				klog.Errorf("Failed to update lb flow for service %s port %+v, err: %s", old.SvcID, *port, err)
				return err
			}
		}
	}

	old.Ports = new.Ports
	if err := r.baseSvcCache.Update(old.DeepCopy()); err != nil {
		klog.Errorf("Failed to update baseSvc cache for service %+v, err: %s", old, err)
		return err
	}

	return nil
}

func (r *Reconcile) processUpdateSessionAffinityOfService(new *proxycache.BaseSvc, old *proxycache.BaseSvc) error {
	if new == nil || old == nil {
		klog.Errorf("Missing service old or new info, old is %+v, new is %+v", old, new)
		return fmt.Errorf("missing service old or new info")
	}

	dpNatBrs := r.DpMgr.GetNatBridges()
	if old.ChangeAffinityMode(new) {
		if new.SessionAffinity == corev1.ServiceAffinityNone {
			for i := range dpNatBrs {
				if err := dpNatBrs[i].DelSessionAffinity(new.SvcID); err != nil {
					klog.Errorf("Failed to update service %s session affinity config to 'None', err: %s", new.SvcID, err)
					return err
				}
			}
		} else {
			if new.SessionAffinityTimeout <= 0 {
				klog.Errorf("Invalid SessionAffinityTimeout %d", new.SessionAffinityTimeout)
			} else {
				timeout := new.SessionAffinityTimeout
				for i := range dpNatBrs {
					if err := dpNatBrs[i].AddSessionAffinity(new.SvcID, new.ClusterIPs, new.ListPorts(), timeout); err != nil {
						klog.Errorf("Failed to update service %s session affinity config to 'ClientIP' with session affinitytiemout %d, err: %s", new.SvcID, timeout, err)
						return err
					}
				}
			}
		}
	} else {
		if new.SessionAffinity == corev1.ServiceAffinityClientIP && old.ChangeAffinityTimeout(new) {
			timeout := new.SessionAffinityTimeout
			for i := range dpNatBrs {
				if err := dpNatBrs[i].UpdateSessionAffinityTimeout(new.SvcID, new.ClusterIPs, new.ListPorts(), timeout); err != nil {
					klog.Errorf("Failed to update service %s session affinity config to 'ClientIP' with session affinitytiemout %d, err: %s", new.SvcID, timeout, err)
					return err
				}
			}
		}
	}

	old.SessionAffinity = new.SessionAffinity
	old.SessionAffinityTimeout = new.SessionAffinityTimeout
	if err := r.baseSvcCache.Update(old.DeepCopy()); err != nil {
		klog.Errorf("Failed to update %+v to baseSvc cache, err: %s", *old, err)
		return err
	}
	return nil
}

func (r *Reconcile) updateServicePort(ctx context.Context, servicePort *everoutesvc.ServicePort) error {
	if servicePort == nil {
		return nil
	}

	// The r.svcPortCache update first to prevent data loss.
	// If r.svcPortCache update in last, consider this case: r.backendCache update success and r.svcPortCache update failed,
	// the ServicePort resource has been deleted before servicePort controller reconcile, then, r.backendCache don't know the
	// deleted servicePort's related service and portname and it can't update itself.
	svcPortKey := proxycache.GenSvcPortKey(servicePort.GetNamespace(), servicePort.GetName())
	old, exists, err := r.svcPortCache.GetByKey(svcPortKey)
	if err != nil {
		klog.Errorf("Failed to get svcPortCache for servicePort: %s, err: %s", svcPortKey, err)
	}
	// There is one-to-one correspondence between servicePort and service/portName, so don't need update cache when it exists
	if !exists || old == nil {
		portCache := proxycache.GenSvcPortFromServicePort(servicePort)
		if portCache != nil {
			if err := r.svcPortCache.Add(portCache); err != nil {
				klog.Errorf("Failed to add svcPortcache for svcPort %+v, err: %s", *portCache, err)
				return err
			}
		}
	}

	var err1, err2 error
	var wg sync.WaitGroup
	wg.Add(2)
	go func(servicePort *everoutesvc.ServicePort) {
		defer wg.Done()
		if err1 = r.updateServicePortForGroup(servicePort); err1 != nil {
			klog.Errorf("Failed to update or create servicePort %+v for update related ovsgroup, err: %s", servicePort, err1)
		}
	}(servicePort)

	go func(servicePort *everoutesvc.ServicePort) {
		defer wg.Done()
		if err2 = r.updateServicePortForBackend(servicePort); err2 != nil {
			klog.Errorf("Failed to update or create servicePort %+v for update related backend, err: %s", servicePort, err2)
		}
	}(servicePort)

	wg.Wait()

	if err1 == nil && err2 == nil {
		return nil
	}

	return fmt.Errorf("update servicePort for group err is %s, update servicePort for backend err is %s", err1, err2)
}

func (r *Reconcile) updateServicePortForGroup(servicePort *everoutesvc.ServicePort) error {
	if servicePort == nil {
		return nil
	}

	svcID := proxycache.GenSvcID(servicePort.GetNamespace(), servicePort.Spec.SvcRef)
	dpNatBrs := r.DpMgr.GetNatBridges()
	for i := range dpNatBrs {
		dpNatBr := dpNatBrs[i]
		if err := dpNatBr.UpdateLBGroup(svcID, servicePort.Spec.PortName, servicePort.Spec.Backends); err != nil {
			klog.Errorf("Failed to update lb group for servicePort %+v of service: %s, err: %s", servicePort, svcID, err)
			return err
		}
	}

	klog.Infof("Success update ServicePort %+v for group", *servicePort)
	return nil
}

func (r *Reconcile) updateServicePortForBackend(servicePort *everoutesvc.ServicePort) error {
	if servicePort == nil {
		return nil
	}
	if err := r.deleteBackendSvcPortRef(servicePort); err != nil {
		klog.Errorf("Failed to delete backend svcPortRef from backend cache for svc %+v, err: %s", *servicePort, err)
		return err
	}
	if err := r.addBackendSvcPortRef(servicePort); err != nil {
		klog.Errorf("Failed to add backend svcPortRef to backend cache for svc %+v, err: %s", *servicePort, err)
		return err
	}
	klog.Infof("Success update ServicePort %+v for backend", *servicePort)
	return nil
}

func (r *Reconcile) deleteBackendSvcPortRef(servicePort *everoutesvc.ServicePort) error {
	if servicePort == nil {
		return nil
	}

	svcPortRef := proxycache.GenServicePortRef(servicePort.Namespace, servicePort.Spec.SvcRef, servicePort.Spec.PortName)
	oldBackends, err := r.backendCache.ByIndex(proxycache.ServicePortIndex, svcPortRef)
	if err != nil {
		klog.Errorf("Failed get ServicePort %+v related old backends, err: %s", *servicePort, err)
		return err
	}

	dpNatBrs := r.DpMgr.GetNatBridges()
	for i := range oldBackends {
		if oldBackends[i] == nil {
			continue
		}
		old := oldBackends[i].(*proxycache.Backend).DeepCopy()
		portDelete := true
		for j := range servicePort.Spec.Backends {
			cur := servicePort.Spec.Backends[j]
			if old.Port == cur.Port && old.IP == cur.IP && old.Protocol == cur.Protocol {
				portDelete = false
				break
			}
		}
		if portDelete {
			old.ServicePortRefs.Delete(svcPortRef)
			if old.ServicePortRefs.Len() == 0 {
				for k := range dpNatBrs {
					if err := dpNatBrs[k].DelDnatFlow(old.IP, old.Protocol, old.Port); err != nil {
						klog.Errorf("Failed to delete dnat flow for backend %+v, service port %s, err: %s", old, svcPortRef, err)
						return err
					}
				}
				if err := r.backendCache.Delete(old); err != nil {
					klog.Errorf("Failed to delete backend %+v from backend cache for svc port %s, err: %s", old, svcPortRef, err)
					return err
				}
			} else {
				if err := r.backendCache.Update(old); err != nil {
					klog.Errorf("Failed to update backend svcPortRef %+v from backend cache for svc port %s, err: %s", old, svcPortRef, err)
					return err
				}
			}
		}
	}
	return nil
}

func (r *Reconcile) addBackendSvcPortRef(servicePort *everoutesvc.ServicePort) error {
	if servicePort == nil {
		return nil
	}
	dpNatBrs := r.DpMgr.GetNatBridges()
	svcPortRef := proxycache.GenServicePortRef(servicePort.Namespace, servicePort.Spec.SvcRef, servicePort.Spec.PortName)
	for i := range servicePort.Spec.Backends {
		cur := servicePort.Spec.Backends[i]
		key := proxycache.GenBackendKey(cur.IP, cur.Port, cur.Protocol)
		oldObj, exists, err := r.backendCache.GetByKey(key)
		if err != nil {
			klog.Errorf("Failed to get related backend %s from backend cache, err: %s", key, err)
			return err
		}
		if !exists || oldObj == nil {
			new := servicePortBackendToCacheBackend(cur)
			new.ServicePortRefs = sets.NewString(svcPortRef)
			for i := range dpNatBrs {
				if err := dpNatBrs[i].AddDNATFlow(new.IP, new.Protocol, new.Port); err != nil {
					klog.Errorf("Failed to add a dnat flow for backend %+v, service port %s, err: %s", cur, svcPortRef, err)
					return err
				}
			}
			if err := r.backendCache.Add(&new); err != nil {
				klog.Errorf("Failed to add a new backend %+v to backend cache, err: %s", new, err)
				return err
			}
		} else {
			old := oldObj.(*proxycache.Backend).DeepCopy()
			old.ServicePortRefs.Insert(svcPortRef)
			if err := r.backendCache.Update(old); err != nil {
				klog.Errorf("Failed to update backend %+v to backend cache, err: %s", old, err)
				return err
			}
		}
	}

	return nil
}

func (r *Reconcile) deleteServicePort(ctx context.Context, namespacedName types.NamespacedName) error {
	oldObj, exists, err := r.svcPortCache.GetByKey(proxycache.GenSvcPortKey(namespacedName.Namespace, namespacedName.Name))
	if err != nil {
		klog.Errorf("Failed to get SvcPort cache for ServicePort %+v, err: %s", namespacedName, err)
		return err
	}
	if !exists || oldObj == nil {
		klog.Infof("Can't find SvcPort cache for delete ServicePort %+v, skip it", namespacedName)
		return nil
	}
	old := oldObj.(*proxycache.SvcPort)

	var err1, err2 error
	var wg sync.WaitGroup
	wg.Add(2)
	go func(svcPort *proxycache.SvcPort) {
		defer wg.Done()
		if err1 = r.deleteServicePortForGroup(svcPort); err1 != nil {
			klog.Errorf("Failed to delete servicePort %+v for delete related ovsgroup, err: %s", svcPort, err1)
		}
	}(old)

	go func(svcPort *proxycache.SvcPort) {
		defer wg.Done()
		if err2 = r.deleteServicePortForBackend(svcPort); err2 != nil {
			klog.Errorf("Failed to delete servicePort %+v for delete related backend, err: %s", svcPort, err2)
		}
	}(old)

	wg.Wait()

	if err1 != nil || err2 != nil {
		return fmt.Errorf("deleteServicePortForGroup err is %s, deleteServicePortForBackend err is %s", err1, err2)
	}

	if err := r.svcPortCache.Delete(old); err != nil {
		klog.Errorf("Delete svcPortCache %+v failed, err: %s", old, err)
		return err
	}
	return nil
}

func (r *Reconcile) deleteServicePortForGroup(svcPort *proxycache.SvcPort) error {
	if svcPort == nil {
		return nil
	}
	svcID := proxycache.GenSvcID(svcPort.Namespace, svcPort.SvcName)
	dpNatBrs := r.DpMgr.GetNatBridges()
	for i := range dpNatBrs {
		dpNatBr := dpNatBrs[i]
		if err := dpNatBr.ResetLBGroup(svcID, svcPort.PortName); err != nil {
			klog.Errorf("Failed to reset service %s group for port %s, err: %s", svcID, svcPort.PortName, err)
			return err
		}
	}
	klog.Infof("Success delete ServicePort %+v for group", *svcPort)
	return nil
}

func (r *Reconcile) deleteServicePortForBackend(svcPort *proxycache.SvcPort) error {
	if svcPort == nil {
		return nil
	}
	svcPortRef := proxycache.GenServicePortRef(svcPort.Namespace, svcPort.SvcName, svcPort.PortName)
	backends, err := r.backendCache.ByIndex(proxycache.ServicePortIndex, svcPortRef)
	if err != nil {
		klog.Errorf("Failed to get SvcPort %+v related backends, err: %s", *svcPort, err)
		return err
	}

	dpNatBrs := r.DpMgr.GetNatBridges()
	for i := range backends {
		if backends[i] == nil {
			continue
		}
		b := backends[i].(*proxycache.Backend).DeepCopy()
		b.ServicePortRefs.Delete(svcPortRef)
		if b.ServicePortRefs.Len() == 0 {
			for j := range dpNatBrs {
				if err := dpNatBrs[j].DelDnatFlow(b.IP, b.Protocol, b.Port); err != nil {
					klog.Errorf("Failed to delete dnat flow for backend %+v, svc port: %s, err: %s", b, svcPortRef, err)
					return err
				}
			}
			if err := r.backendCache.Delete(b); err != nil {
				klog.Errorf("Failed to delete backend %+v from backend cache, err: %s", b, err)
				return err
			}
		} else {
			if err := r.backendCache.Update(b); err != nil {
				klog.Errorf("Failed to update backend %+v from backend cache, err: %s", b, err)
				return err
			}
		}
	}
	klog.Infof("Success delete ServicePort %+v for backend", *svcPort)
	return nil
}

func servicePortBackendToCacheBackend(svcBackend everoutesvc.Backend) proxycache.Backend {
	return proxycache.Backend{
		IP:       svcBackend.IP,
		Protocol: svcBackend.Protocol,
		Port:     svcBackend.Port,
		Node:     svcBackend.Node,
	}
}
