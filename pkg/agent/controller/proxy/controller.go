package proxy

import (
	"context"
	"fmt"
	"sync"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilerr "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	proxycache "github.com/everoute/everoute/pkg/agent/controller/proxy/cache"
	"github.com/everoute/everoute/pkg/agent/datapath"
	everoutesvc "github.com/everoute/everoute/pkg/apis/service/v1alpha1"
	ersource "github.com/everoute/everoute/pkg/source"
	ertype "github.com/everoute/everoute/pkg/types"
)

type Cache struct {
	svcLBCache   cache.Indexer
	svcPortCache cache.Indexer
	backendCache cache.Indexer
}

func (c *Cache) GetCacheBySvcID(svcID string) ([]*proxycache.SvcLB, []*proxycache.Backend, []string) {
	svcLBObjs, _ := c.svcLBCache.ByIndex(proxycache.SvcIDIndex, svcID)
	var svcLBs []*proxycache.SvcLB
	for i := range svcLBObjs {
		svcLBs = append(svcLBs, svcLBObjs[i].(*proxycache.SvcLB))
	}

	var svcPortNames []string
	var backends []*proxycache.Backend
	svcPortObjs, _ := c.svcPortCache.ByIndex(proxycache.SvcIDIndex, svcID)
	for i := range svcPortObjs {
		svcPort := svcPortObjs[i].(*proxycache.SvcPort)
		svcPortNames = append(svcPortNames, svcPort.PortName)
		backendObjs, _ := c.backendCache.ByIndex(proxycache.SvcPortIndex, proxycache.GenSvcPortIndexBySvcID(svcID, svcPort.PortName))
		for i := range backendObjs {
			backends = append(backends, backendObjs[i].(*proxycache.Backend).DeepCopy())
		}
	}

	return svcLBs, backends, svcPortNames
}

// Reconciler watch Service related resource and implement Service
type Reconciler struct {
	client.Client
	Scheme *runtime.Scheme
	DpMgr  *datapath.DpManager

	LocalNode string
	ProxyAll  bool

	SyncChan chan event.GenericEvent
	syncLock sync.RWMutex

	Cache
}

func (r *Reconciler) GetCache() *Cache {
	return &r.Cache
}

// ReconcileService receive Service from work queue
func (r *Reconciler) ReconcileService(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.syncLock.RLock()
	defer r.syncLock.RUnlock()

	klog.Infof("Receive Service %+v reconcile", req.NamespacedName)
	var svc corev1.Service
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

	if filterOutSvc(&svc) {
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
func (r *Reconciler) ReconcileServicePort(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.syncLock.RLock()
	defer r.syncLock.RUnlock()

	klog.Infof("Receive ServicePort %+v reconcile", req.NamespacedName)
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

// ReconcileSync receive proxySuncEvent from work queue
func (r *Reconciler) ReconcileSync(_ context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.syncLock.Lock()
	defer r.syncLock.Unlock()

	klog.Infof("Receive proxy sync event: %+v", req)
	syncType := ersource.SyncType(req.Namespace)
	var err error
	switch syncType {
	case ersource.ReplayType:
		err = r.replay()
	default:
		klog.Errorf("Invalid proxy sync event: %+v, skip", req)
		return ctrl.Result{}, nil
	}
	if err != nil {
		klog.Errorf("Failed to sync proxy dp flows and groups for sync event %+v, err: %s", req, err)
	} else {
		klog.Infof("Success to sync proxy dp flows and groups for sync event %+v", req)
	}
	return ctrl.Result{}, err
}

// SetupWithManager add service controller and servicePort controller to mgr
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	if mgr == nil {
		return fmt.Errorf("can't setup with nil manager")
	}

	if r.LocalNode == "" {
		return fmt.Errorf("can't setup without local node")
	}

	if r.svcLBCache == nil {
		r.svcLBCache = proxycache.NewSvcLBCache()
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

	if err := svcController.Watch(source.Kind(mgr.GetCache(), &corev1.Service{}), &handler.EnqueueRequestForObject{}, predicate.Funcs{
		CreateFunc: predicateCreateSvc,
		UpdateFunc: predicateUpdateSvc,
	}); err != nil {
		return err
	}

	svcPortController, err := controller.New("servicePort controller", mgr, controller.Options{
		Reconciler: reconcile.Func(r.ReconcileServicePort),
	})
	if err != nil {
		return err
	}

	if err := svcPortController.Watch(source.Kind(mgr.GetCache(), &everoutesvc.ServicePort{}), &handler.EnqueueRequestForObject{}); err != nil {
		return err
	}

	syncController, err := controller.New("proxy sync controller", mgr, controller.Options{
		Reconciler: reconcile.Func(r.ReconcileSync),
	})
	if err != nil {
		return err
	}

	return syncController.Watch(&source.Channel{Source: r.SyncChan}, &handler.EnqueueRequestForObject{})
}

func (r *Reconciler) updateService(ctx context.Context, newService *corev1.Service) error {
	svcID := proxycache.GenSvcID(newService.Namespace, newService.Name)
	newLBs, err := proxycache.ServiceToSvcLBs(newService, r.ProxyAll)
	if err != nil {
		klog.Errorf("Failed to transfer service %v to SvcLB cache, err: %s", *newService, err)
		return err
	}
	oldObjs, _ := r.svcLBCache.ByIndex(proxycache.SvcIDIndex, svcID)
	oldLBs := make(map[string]*proxycache.SvcLB, len(oldObjs))
	for i := range oldObjs {
		oldLB := oldObjs[i].(*proxycache.SvcLB).DeepCopy()
		oldLBs[oldLB.ID()] = oldLB
	}

	var errs []error
	add, del, upd := r.diffSvcLBs(oldLBs, newLBs)
	if len(add) > 0 {
		for i := range add {
			if err := r.processSvcLBAdd(newLBs[add[i]]); err != nil {
				klog.Errorf("Failed to add service %s lb info %v related flow, err: %s", svcID, newLBs[add[i]], err)
				errs = append(errs, err)
			}
		}
	}

	if len(del) > 0 {
		for i := range del {
			if err := r.processSvcLBDel(oldLBs[del[i]]); err != nil {
				klog.Errorf("Failed to del service %s old lb info %v related flow, err: %s", svcID, oldLBs[del[i]], err)
				errs = append(errs, err)
			}
		}
	}

	if len(upd) > 0 {
		for i := range upd {
			if err := r.processSvcLBUpd(newLBs[upd[i]], oldLBs[upd[i]]); err != nil {
				klog.Errorf("Failed to update service %s lb info %v related flow, err: %s", svcID, oldLBs[del[i]], err)
				errs = append(errs, err)
			}
		}
	}

	if len(errs) > 0 {
		err := utilerr.NewAggregate(errs)
		klog.Errorf("Failed to update service %s flow, err: %s", svcID, err)
		return err
	}
	return nil
}

func (r *Reconciler) diffSvcLBs(oldLBs, newLBs map[string]*proxycache.SvcLB) ([]string, []string, []string) {
	var add, del, upd []string
	for k, v := range newLBs {
		old, exists := oldLBs[k]
		if !exists {
			add = append(add, k)
			continue
		}
		if *v != *old {
			upd = append(upd, k)
		}
	}
	for k := range oldLBs {
		_, exists := newLBs[k]
		if !exists {
			del = append(del, k)
		}
	}
	return add, del, upd
}

func (r *Reconciler) deleteService(ctx context.Context, svcNamespacedName types.NamespacedName) error {
	svcID := proxycache.GenSvcID(svcNamespacedName.Namespace, svcNamespacedName.Name)

	objs, _ := r.svcLBCache.ByIndex(proxycache.SvcIDIndex, svcID)
	if len(objs) == 0 {
		return nil
	}

	var errs []error
	for i := range objs {
		svcLB := objs[i].(*proxycache.SvcLB).DeepCopy()
		if err := r.processSvcLBDel(svcLB); err != nil {
			klog.Errorf("Failed delete service %s lb info %v related flow, err: %s", svcID, *svcLB, err)
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		err := utilerr.NewAggregate(errs)
		klog.Errorf("Failed to delete service %s, err: %s", svcID, err)
		return err
	}

	return nil
}

func (r *Reconciler) processSvcLBAdd(l *proxycache.SvcLB) error {
	if !l.Valid() {
		return fmt.Errorf("invalid svcLB %v", *l)
	}
	dpNatBrs := r.DpMgr.GetNatBridges()

	// lb flow
	for i := range dpNatBrs {
		dpNatBr := dpNatBrs[i]
		if err := dpNatBr.AddLBFlow(l); err != nil {
			klog.Errorf("Failed to add service LB flow for lb info %v, err: %s", *l, err)
			return err
		}
	}
	lCopy := *l
	lCopy.ResetSessionAffinityConfig()
	_ = r.svcLBCache.Add(&lCopy)

	// session flow
	for i := range dpNatBrs {
		dpNatBr := dpNatBrs[i]
		if err := dpNatBr.AddSessionAffinityFlow(l); err != nil {
			klog.Errorf("Failed to add service session affinity flow for lb info %v, err: %s", *l, err)
			return err
		}
	}
	_ = r.svcLBCache.Update(l)
	klog.Infof("Success to add svcLB %s", l.ID())
	return nil
}

func (r *Reconciler) processSvcLBDel(l *proxycache.SvcLB) error {
	if !l.Valid() {
		return fmt.Errorf("invalid svcLB %+v", *l)
	}
	dpNatBrs := r.DpMgr.GetNatBridges()

	if l.SessionAffinity == corev1.ServiceAffinityClientIP {
		// session flow
		for i := range dpNatBrs {
			dpNatBr := dpNatBrs[i]
			if err := dpNatBr.DelSessionAffinityFlow(l); err != nil {
				klog.Errorf("Failed to del service session affinity flow for lb info %v, err: %s", *l, err)
				return err
			}
		}
		l.ResetSessionAffinityConfig()
		_ = r.svcLBCache.Update(l)
	}

	// lb flow
	svcPortName := proxycache.GenSvcPortIndexBySvcID(l.SvcID, l.Port.Name)
	//svcPortRefs, _ := r.svcLBCache.ByIndex(proxycache.SvcPortIndex, svcPortName)
	if r.shouldDelGroupWhenDelSvcLB(l.ID(), svcPortName) {
		// delete group in dp
		if err := r.deleteServicePortForGroup(l.SvcID, l.Port.Name); err != nil {
			klog.Errorf("Failed to delete group for service %s port %s, err: %s", l.SvcID, l.Port.Name, err)
			return err
		}
	}
	for i := range dpNatBrs {
		dpNatBr := dpNatBrs[i]
		if err := dpNatBr.DelLBFlow(l); err != nil {
			klog.Errorf("Failed to delete service LB flow for lb info %v, err: %s", *l, err)
			return err
		}
	}
	_ = r.svcLBCache.Delete(l)
	klog.Infof("Success to delete svcLB %s", l.ID())
	return nil
}

func (r *Reconciler) processSvcLBUpd(newLB, oldLB *proxycache.SvcLB) error {
	if !newLB.Valid() {
		return fmt.Errorf("invalid new svcLB %v", *newLB)
	}
	if !oldLB.Valid() {
		return fmt.Errorf("invalid old svcLB %v", *oldLB)
	}

	if newLB.Port != oldLB.Port {
		if err := r.processSvcLBDel(oldLB); err != nil {
			klog.Errorf("Failed to delete old service lb info %v related flow, err: %s", *oldLB, err)
			return err
		}
		if err := r.processSvcLBAdd(newLB); err != nil {
			klog.Errorf("Failed to delete new service lb info %v related flow, err: %s", *newLB, err)
			return err
		}
		return nil
	}

	dpNatBrs := r.DpMgr.GetNatBridges()
	if newLB.TrafficPolicy != oldLB.TrafficPolicy {
		for i := range dpNatBrs {
			dpNatBr := dpNatBrs[i]
			if err := dpNatBr.DelLBFlow(oldLB); err != nil {
				klog.Errorf("Failed to del service LB flow for old lb info %v, err: %s", *oldLB, err)
				return err
			}
			if err := dpNatBr.AddLBFlow(newLB); err != nil {
				klog.Errorf("Failed to add service LB flow for new lb info %v, err: %s", *newLB, err)
				return err
			}
		}
		oldLB.TrafficPolicy = newLB.TrafficPolicy
		_ = r.svcLBCache.Update(oldLB)
		klog.Infof("Success to update svcLB %s traffic policy to %s", oldLB.ID(), newLB.TrafficPolicy)
	}

	if newLB.SessionAffinity != oldLB.SessionAffinity || newLB.SessionAffinityTimeout != oldLB.SessionAffinityTimeout {
		for i := range dpNatBrs {
			dpNatBr := dpNatBrs[i]
			if err := dpNatBr.DelSessionAffinityFlow(oldLB); err != nil {
				klog.Errorf("Failed to del service session affinity flow for old lb info %v, err: %s", *oldLB, err)
				return err
			}
			if err := dpNatBr.AddSessionAffinityFlow(newLB); err != nil {
				klog.Errorf("Failed to add service session affinity flow for new lb info %v, err: %s", *newLB, err)
				return err
			}
		}
		oldLB.SessionAffinity = newLB.SessionAffinity
		oldLB.SessionAffinityTimeout = newLB.SessionAffinityTimeout
		_ = r.svcLBCache.Update(oldLB)
		klog.Infof("Success to update svcLB %s sessionAffinity to %s/%d", oldLB.ID(), newLB.SessionAffinity, newLB.SessionAffinityTimeout)
	}
	return nil
}

func (r *Reconciler) updateServicePort(ctx context.Context, servicePort *everoutesvc.ServicePort) error {
	svcPortKey := proxycache.GenSvcPortKey(servicePort.GetNamespace(), servicePort.GetName())

	// update group
	if err := r.updateServicePortForGroup(servicePort); err != nil {
		klog.Errorf("Failed to update group for service port %s, err: %s", svcPortKey, err)
		return err
	}
	portCache := proxycache.GenSvcPortFromServicePort(servicePort)
	_, exists, _ := r.svcPortCache.GetByKey(svcPortKey)
	// There is one-to-one correspondence between servicePort and service/portName, so don't need update cache when it exists
	if !exists {
		_ = r.svcPortCache.Add(portCache)
	} else {
		_ = r.svcPortCache.Update(portCache)
	}

	// update backends
	if err := r.updateServicePortForBackend(servicePort); err != nil {
		klog.Errorf("Failed to update backends for service port %s, err: %s", svcPortKey, err)
		return err
	}
	return nil
}

func (r *Reconciler) updateServicePortForGroup(servicePort *everoutesvc.ServicePort) error {
	if servicePort == nil {
		return nil
	}

	svcID := proxycache.GenSvcID(servicePort.GetNamespace(), servicePort.Spec.SvcRef)
	for _, tp := range []ertype.TrafficPolicyType{ertype.TrafficPolicyCluster, ertype.TrafficPolicyLocal} {
		bks := r.filterServicePortBackends(servicePort.Spec.Backends, tp)
		dpNatBrs := r.DpMgr.GetNatBridges()
		for i := range dpNatBrs {
			dpNatBr := dpNatBrs[i]
			if err := dpNatBr.UpdateLBGroup(svcID, servicePort.Spec.PortName, bks, tp); err != nil {
				klog.Errorf("Failed to update lb group for traffic policy %s servicePort %+v of service: %s, err: %s", tp, servicePort, svcID, err)
				return err
			}
		}
	}

	svcPortName := proxycache.GenServicePortRef(servicePort.GetNamespace(), servicePort.Spec.SvcRef, servicePort.Spec.PortName)
	klog.Infof("Success update ServicePort %s for group", svcPortName)
	return nil
}

func (r *Reconciler) updateServicePortForBackend(servicePort *everoutesvc.ServicePort) error {
	svcPortIndex := proxycache.GenServicePortRef(servicePort.GetNamespace(), servicePort.Spec.SvcRef, servicePort.Spec.PortName)
	objs, _ := r.backendCache.ByIndex(proxycache.SvcPortIndex, svcPortIndex)
	oldBackends := make(map[string]*proxycache.Backend, len(objs))
	for i := range objs {
		b := objs[i].(*proxycache.Backend).DeepCopy()
		oldBackends[proxycache.GenBackendKey(b.IP, b.Port, b.Protocol)] = b
	}
	newBackends := make(map[string]*proxycache.Backend, len(servicePort.Spec.Backends))
	for i := range servicePort.Spec.Backends {
		b := servicePortBackendToCacheBackend(servicePort.Spec.Backends[i])
		newBackends[proxycache.GenBackendKey(b.IP, b.Port, b.Protocol)] = &b
	}

	var errs []error
	dpNatBrs := r.DpMgr.GetNatBridges()
	for k, v := range newBackends {
		obj, exists, _ := r.backendCache.GetByKey(k)
		if exists {
			old := obj.(*proxycache.Backend).DeepCopy()
			if old.Node != v.Node {
				// impossible situation
				klog.Warningf("Update backend %v node from %s to %s", k, old.Node, v.Node)
				old.Node = v.Node
				_ = r.backendCache.Update(old)
			}
			if !old.ServicePortRefs.Has(svcPortIndex) {
				old.ServicePortRefs.Insert(svcPortIndex)
				_ = r.backendCache.Update(old)
			}
			continue
		}

		var localErrs []error
		for i := range dpNatBrs {
			dpNatBr := dpNatBrs[i]
			if err := dpNatBr.AddDnatFlow(v.IP, v.Protocol, v.Port); err != nil {
				klog.Errorf("Failed to add dnat flow for backend %s, err: %s", k, err)
				localErrs = append(localErrs, err)
			}
		}
		if len(localErrs) > 0 {
			errs = append(errs, localErrs...)
		}
		v.ServicePortRefs = sets.NewString(svcPortIndex)
		_ = r.backendCache.Add(v)
	}

	for k, v := range oldBackends {
		_, exists := newBackends[k]
		if exists {
			continue
		}
		v.ServicePortRefs.Delete(svcPortIndex)
		if v.ServicePortRefs.Len() > 0 {
			_ = r.backendCache.Update(v)
			continue
		}
		var localErrs []error
		for i := range dpNatBrs {
			dpNatBr := dpNatBrs[i]
			if err := dpNatBr.DelDnatFlow(v.IP, v.Protocol, v.Port); err != nil {
				klog.Errorf("Failed to del dnat flow for backend %s, err: %s", k, err)
				localErrs = append(localErrs, err)
			}
		}
		if len(localErrs) > 0 {
			errs = append(errs, localErrs...)
			continue
		}
		_ = r.backendCache.Delete(v)
	}

	if len(errs) > 0 {
		err := utilerr.NewAggregate(errs)
		klog.Errorf("Failed to update servicePort %s for backend, err: %s", svcPortIndex, err)
		return err
	}
	klog.Infof("Success to update servicePort %s for backend", svcPortIndex)
	return nil
}

func (r *Reconciler) deleteServicePort(ctx context.Context, namespacedName types.NamespacedName) error {
	oldObj, exists, _ := r.svcPortCache.GetByKey(proxycache.GenSvcPortKey(namespacedName.Namespace, namespacedName.Name))
	if !exists {
		klog.Infof("Can't find SvcPort cache for delete ServicePort %+v, skip it", namespacedName)
		return nil
	}
	old := oldObj.(*proxycache.SvcPort).DeepCopy()
	svcID := proxycache.GenSvcID(old.Namespace, old.SvcName)
	portNameIndex := proxycache.GenSvcPortIndex(old.Namespace, old.SvcName, old.PortName)

	if err := r.deleteServicePortForBackend(svcID, old.PortName); err != nil {
		klog.Errorf("Failed to delete backend for servicePort %s, err: %s", portNameIndex, err)
		return err
	}

	objs, _ := r.svcLBCache.ByIndex(proxycache.SvcPortIndex, portNameIndex)
	if len(objs) > 0 {
		// reset serviceport
		if err := r.resetServicePortForGroup(svcID, old.PortName); err != nil {
			klog.Errorf("Failed to reset group for servicePort %s, err: %s", portNameIndex, err)
			return err
		}
	} else {
		if err := r.deleteServicePortForGroup(svcID, old.PortName); err != nil {
			klog.Errorf("Failed to delete group for servicePort %s, err: %s", portNameIndex, err)
			return err
		}
	}

	_ = r.svcPortCache.Delete(old)
	return nil
}

func (r *Reconciler) deleteServicePortForGroup(svcID, portName string) error {
	dpNatBrs := r.DpMgr.GetNatBridges()
	for i := range dpNatBrs {
		dpNatBr := dpNatBrs[i]
		if err := dpNatBr.DelLBGroup(svcID, portName); err != nil {
			klog.Errorf("Failed to del service %s group for port %s, err: %s", svcID, portName, err)
			return err
		}
	}
	klog.Infof("Success delete service %s port %s for group", svcID, portName)
	return nil
}

func (r *Reconciler) resetServicePortForGroup(svcID, portName string) error {
	dpNatBrs := r.DpMgr.GetNatBridges()
	for i := range dpNatBrs {
		dpNatBr := dpNatBrs[i]
		if err := dpNatBr.ResetLBGroup(svcID, portName); err != nil {
			klog.Errorf("Failed to reset service %s group for port %s, err: %s", svcID, portName, err)
			return err
		}
	}
	klog.Infof("Success reset service %s port %s for group", svcID, portName)
	return nil
}

func (r *Reconciler) deleteServicePortForBackend(svcID, portName string) error {
	svcPortRef := proxycache.GenSvcPortIndexBySvcID(svcID, portName)
	backends, _ := r.backendCache.ByIndex(proxycache.SvcPortIndex, svcPortRef)

	dpNatBrs := r.DpMgr.GetNatBridges()
	for i := range backends {
		b := backends[i].(*proxycache.Backend).DeepCopy()
		b.ServicePortRefs.Delete(svcPortRef)
		if b.ServicePortRefs.Len() == 0 {
			for j := range dpNatBrs {
				if err := dpNatBrs[j].DelDnatFlow(b.IP, b.Protocol, b.Port); err != nil {
					klog.Errorf("Failed to delete dnat flow for backend %+v, svc port: %s, err: %s", b, svcPortRef, err)
					return err
				}
			}
			_ = r.backendCache.Delete(b)
		} else {
			_ = r.backendCache.Update(b)
		}
	}
	klog.Infof("Success delete ServicePort %s for backend", svcPortRef)
	return nil
}

func (r *Reconciler) shouldDelGroupWhenDelSvcLB(delSvcLBID, svcPortName string) bool {
	objs, _ := r.svcPortCache.ByIndex(proxycache.SvcPortIndex, svcPortName)
	if len(objs) > 0 {
		return false
	}

	res, _ := r.svcLBCache.ByIndex(proxycache.SvcPortIndex, svcPortName)
	if len(res) == 0 {
		klog.Warningf("The servicePort %s should be referenced by svclb %s, but not", svcPortName, delSvcLBID)
		return true
	}
	if len(res) > 1 {
		return false
	}
	svcLB := res[0].(*proxycache.SvcLB).DeepCopy()
	if svcLB.ID() == delSvcLBID {
		return true
	}
	klog.Warningf("The servicePort %s should be referenced by svclb %s, but not", svcPortName, delSvcLBID)
	return false
}

func (r *Reconciler) replay() error {
	dpNatBrs := r.DpMgr.GetNatBridges()

	var err1, err2, err3 error
	var wg sync.WaitGroup
	wg.Add(2)

	// replay groups
	go func(dpNatBrs []*datapath.NatBridge) {
		defer wg.Done()
		if err1 = r.replayGroup(dpNatBrs); err1 != nil {
			klog.Errorf("Failed to replay group for nat bridge, err: %s", err1)
		}
	}(dpNatBrs)

	// replay dnat flows
	go func(dpNatBrs []*datapath.NatBridge) {
		defer wg.Done()
		if err3 = r.replayDnatFlows(dpNatBrs); err3 != nil {
			klog.Errorf("Failed to replay dnat flows for nat bridge, err: %s", err3)
		}
	}(dpNatBrs)

	wg.Wait()

	// replay service lb flows
	if err2 = r.replayLBFlows(dpNatBrs); err2 != nil {
		klog.Errorf("Failed to replay lb flows for nat bridge, err: %s", err2)
	}

	if err1 != nil || err2 != nil || err3 != nil {
		return fmt.Errorf("failed to replay proxy flows and groups")
	}

	klog.Info("Success replay proxy flows and groups")
	return nil
}

func (r *Reconciler) replayGroup(dpNatBrs []*datapath.NatBridge) error {
	svcPortObjList := r.svcPortCache.List()
	for i := range svcPortObjList {
		if svcPortObjList[i] == nil {
			continue
		}
		svcPort := svcPortObjList[i].(*proxycache.SvcPort)
		svcPortRef := proxycache.GenServicePortRef(svcPort.Namespace, svcPort.SvcName, svcPort.PortName)
		bkObjList, err := r.backendCache.ByIndex(proxycache.SvcPortIndex, svcPortRef)
		if err != nil {
			klog.Errorf("Failed to list backend for svcPortRef %s, err: %s", svcPortRef, err)
			return err
		}
		var svcBackends []everoutesvc.Backend
		for j := range bkObjList {
			if bkObjList[j] == nil {
				continue
			}
			bk := bkObjList[j].(*proxycache.Backend)
			svcBackends = append(svcBackends, cacheBackendToServicePortBackend(*bk))
		}
		if len(svcBackends) == 0 {
			continue
		}
		for _, tp := range []ertype.TrafficPolicyType{ertype.TrafficPolicyCluster, ertype.TrafficPolicyLocal} {
			bks := r.filterServicePortBackends(svcBackends, tp)
			svcID := proxycache.GenSvcID(svcPort.Namespace, svcPort.SvcName)
			for i := range dpNatBrs {
				dpNatBr := dpNatBrs[i]
				if err := dpNatBr.UpdateLBGroup(svcID, svcPort.PortName, bks, tp); err != nil {
					klog.Errorf("Failed to replay lb group for servicePort %s traffic policy %s, err: %s", svcPortRef, tp, err)
					return err
				}
			}
		}
	}
	return nil
}

func (r *Reconciler) replayLBFlows(dpNatBrs []*datapath.NatBridge) error {
	svcObjList := r.svcLBCache.List()
	for i := range svcObjList {
		if svcObjList[i] == nil {
			continue
		}
		svcLB := svcObjList[i].(*proxycache.SvcLB)
		for i := range dpNatBrs {
			if err := dpNatBrs[i].AddLBFlow(svcLB); err != nil {
				klog.Errorf("Failed to add lb flow for svc lb info %v, err: %s", *svcLB, err)
				return err
			}
			if err := dpNatBrs[i].AddSessionAffinityFlow(svcLB); err != nil {
				klog.Errorf("Failed to add session affinity flow for svc lb info %v, err: %s", *svcLB, err)
			}
		}
	}
	return nil
}

func (r *Reconciler) replayDnatFlows(dpNatBrs []*datapath.NatBridge) error {
	bkObjList := r.backendCache.List()
	for i := range bkObjList {
		if bkObjList[i] == nil {
			continue
		}
		bk := bkObjList[i].(*proxycache.Backend)
		for i := range dpNatBrs {
			if err := dpNatBrs[i].AddDnatFlow(bk.IP, bk.Protocol, bk.Port); err != nil {
				klog.Errorf("Failed to add a dnat flow for backend %+v, err: %s", bk, err)
				return err
			}
		}
	}
	return nil
}

func (r *Reconciler) filterServicePortBackends(bks []everoutesvc.Backend, tp ertype.TrafficPolicyType) []everoutesvc.Backend {
	if tp == ertype.TrafficPolicyCluster {
		return bks
	}

	res := make([]everoutesvc.Backend, 0)
	for _, b := range bks {
		if b.Node != r.LocalNode {
			continue
		}
		res = append(res, b)
	}
	return res
}

func servicePortBackendToCacheBackend(svcBackend everoutesvc.Backend) proxycache.Backend {
	return proxycache.Backend{
		IP:       svcBackend.IP,
		Protocol: svcBackend.Protocol,
		Port:     svcBackend.Port,
		Node:     svcBackend.Node,
	}
}

func cacheBackendToServicePortBackend(cacheBackend proxycache.Backend) everoutesvc.Backend {
	return everoutesvc.Backend{
		IP:       cacheBackend.IP,
		Protocol: cacheBackend.Protocol,
		Port:     cacheBackend.Port,
		Node:     cacheBackend.Node,
	}
}

func filterOutSvc(svc *corev1.Service) bool {
	if svc.Spec.Type == corev1.ServiceTypeExternalName {
		return true
	}
	if svc.Spec.Type == corev1.ServiceTypeClusterIP {
		if len(svc.Spec.ClusterIPs) == 0 {
			// headless svc
			return true
		}
	}
	return false
}

func predicateCreateSvc(e event.CreateEvent) bool {
	o := e.Object.(*corev1.Service)
	return !filterOutSvc(o)
}

func predicateUpdateSvc(e event.UpdateEvent) bool {
	svcNew := e.ObjectNew.(*corev1.Service)
	svcOld := e.ObjectOld.(*corev1.Service)
	if filterOutSvc(svcNew) && filterOutSvc(svcOld) {
		return false
	}
	return true
}
