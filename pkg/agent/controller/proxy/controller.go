package proxy

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
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

	// todo

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
