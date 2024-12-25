package k8s

import (
	"context"
	// #nosec
	"crypto/md5"
	"encoding/hex"
	"net"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"

	svc "github.com/everoute/everoute/pkg/apis/service/v1alpha1"
)

// EndpointsReconcile watch endpoints to gen servicePort
type EndpointsReconcile struct {
	APIReader client.Reader
	Client    client.Client
	Scheme    *runtime.Scheme
}

// Reconcile receive Endpoints from workqueue, gen servicePort
func (r *EndpointsReconcile) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.Infof("Receive endpoints %v Reconcile", req.NamespacedName)
	svcEp := corev1.Endpoints{}

	err := r.Client.Get(ctx, req.NamespacedName, &svcEp)
	if err != nil {
		if errors.IsNotFound(err) {
			klog.Infof("Delete endpoints %v", req.NamespacedName)
			if err := r.deleteEndpoints(ctx, req.NamespacedName); err != nil {
				klog.Errorf("Failed to reconcile delete endpoints %v, err: %s", req.NamespacedName, err)
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		klog.Errorf("Failed to get endpoints %#v, err: %s", req.NamespacedName, err)
		return ctrl.Result{}, err
	}

	svc := corev1.Service{}
	if err = r.Client.Get(ctx, req.NamespacedName, &svc); err != nil {
		klog.Errorf("Failed to get svc related to  endpoints %#v, err: %s", req.NamespacedName, err)
		return ctrl.Result{}, err
	}
	// filter headless svc,and it may not change once set
	if svc.Spec.ClusterIP == "None" {
		return ctrl.Result{}, nil
	}

	klog.Infof("Add or update endpoints %#v", svcEp)
	if err := r.updateEndpoints(ctx, svcEp); err != nil {
		klog.Errorf("Failed to reconcile add or update endpoints %v, err: %s", svcEp, err)
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// SetupWithManager add endpoints controller to the manager
func (r *EndpointsReconcile) SetupWithManager(mgr ctrl.Manager) error {
	c, err := controller.New("endpoints-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}
	if err := c.Watch(source.Kind(mgr.GetCache(), &corev1.Endpoints{}), &handler.EnqueueRequestForObject{}); err != nil {
		return err
	}

	return c.Watch(source.Kind(mgr.GetCache(), &svc.ServicePort{}), handler.Funcs{
		CreateFunc: r.addServicePort,
	})
}

func (r *EndpointsReconcile) addServicePort(ctx context.Context, e event.CreateEvent, q workqueue.RateLimitingInterface) {
	if e.Object == nil {
		klog.Errorf("Receive create event with no object %v", e)
		return
	}

	namespacedName := types.NamespacedName{
		Namespace: e.Object.GetNamespace(),
		Name:      e.Object.GetLabels()[svc.LabelRefEndpoints],
	}
	err := r.Client.Get(ctx, namespacedName, &corev1.Endpoints{})
	if err == nil {
		// servicePort related endpoints exists, don't need to clear the servicePort
		return
	}

	if errors.IsNotFound(err) {
		klog.Infof("Receive add servicePort event, the servicePort related endpoints %v has been deleted, need to clear servicePort", namespacedName)
	} else {
		klog.Errorf("Receive add servicePort event, Failed to get endpoints %v, err: %s, add to queue", namespacedName, err)
	}
	q.Add(ctrl.Request{NamespacedName: namespacedName})
}

func (r *EndpointsReconcile) deleteEndpoints(ctx context.Context, namespacedName types.NamespacedName) error {
	svcPort := svc.ServicePort{}
	namespaceSelector := client.InNamespace(namespacedName.Namespace)
	labelSelector := client.MatchingLabels{svc.LabelRefEndpoints: namespacedName.Name}
	if err := r.Client.DeleteAllOf(ctx, &svcPort, namespaceSelector, labelSelector); err != nil {
		klog.Errorf("Delete endpoints %v related svcPort failed: %s", namespacedName, err)
		return err
	}

	return nil
}

func (r *EndpointsReconcile) updateEndpoints(ctx context.Context, svcEp corev1.Endpoints) error {
	namespacedName := types.NamespacedName{Namespace: svcEp.Namespace, Name: svcEp.Name}
	oldSvcPorts := svc.ServicePortList{}
	namespaceSelector := client.InNamespace(svcEp.Namespace)
	labelSelector := client.MatchingLabels{svc.LabelRefEndpoints: svcEp.Name}
	if err := r.APIReader.List(ctx, &oldSvcPorts, namespaceSelector, labelSelector); err != nil {
		klog.Errorf("List endpoints %v related svcPort failed: %s", namespacedName, err)
		return err
	}

	oldSvcPortsMap := servicePortListToServicePortMap(oldSvcPorts)
	newSvcPortsMap := genSvcPortFromEndpoints(svcEp)
	addSvcPort, updateSvcPort, deleteSvcPort := compareServicePorts(newSvcPortsMap, oldSvcPortsMap)

	for i := range addSvcPort {
		if err := r.Client.Create(ctx, addSvcPort[i]); err != nil {
			klog.Errorf("Failed to create ServicePort %+v, err: %s", *addSvcPort[i], err)
			return err
		}
	}

	for i := range updateSvcPort {
		if err := r.Client.Update(ctx, updateSvcPort[i]); err != nil {
			klog.Errorf("Failed to update ServicePort %+v, err: %s", *updateSvcPort[i], err)
			return err
		}
	}

	for i := range deleteSvcPort {
		if err := r.Client.Delete(ctx, deleteSvcPort[i]); err != nil {
			klog.Errorf("Failed to delete ServicePort %+v, err: %s", *deleteSvcPort[i], err)
			return err
		}
	}

	return nil
}

func compareServicePorts(new, old map[string]*svc.ServicePort) (addSvcPort, updateSvcPort, deleteSvcPort []*svc.ServicePort) {
	for portName := range new {
		if _, ok := old[portName]; !ok {
			addSvcPort = append(addSvcPort, new[portName])
		} else if !new[portName].Equal(old[portName]) {
			old[portName].Spec = *(new[portName].Spec.DeepCopy())
			updateSvcPort = append(updateSvcPort, old[portName])
		}
	}

	for portName := range old {
		if _, ok := new[portName]; !ok {
			deleteSvcPort = append(deleteSvcPort, old[portName])
		}
	}
	return
}

func genSvcPortName(svcName, portName string) string {
	// #nosec
	sum := md5.Sum([]byte(svcName + "/" + portName))
	return hex.EncodeToString(sum[:])
}

func newSvcPort(epNamespacedName types.NamespacedName, portName string) *svc.ServicePort {
	return &svc.ServicePort{
		ObjectMeta: metav1.ObjectMeta{
			Name:      genSvcPortName(epNamespacedName.Name, portName),
			Namespace: epNamespacedName.Namespace,
			Labels: map[string]string{
				svc.LabelRefEndpoints: epNamespacedName.Name,
			},
		},
		Spec: svc.ServicePortSpec{
			PortName: portName,
			SvcRef:   epNamespacedName.Name,
		},
	}
}

func genSvcPortFromEndpoints(svcEp corev1.Endpoints) map[string]*svc.ServicePort {
	epNamespacedName := types.NamespacedName{Namespace: svcEp.Namespace, Name: svcEp.Name}
	// key is portname
	svcPortsMap := make(map[string]*svc.ServicePort)

	for _, subset := range svcEp.Subsets {
		for _, p := range subset.Ports {
			if p.Protocol != corev1.ProtocolTCP && p.Protocol != corev1.ProtocolUDP {
				klog.Errorf("Unsupport protocol for service endpoints subset port %+v, skip", p)
				continue
			}
			if _, ok := svcPortsMap[p.Name]; !ok {
				svcPortsMap[p.Name] = newSvcPort(epNamespacedName, p.Name)
			}
			for _, a := range subset.Addresses {
				if net.ParseIP(a.IP).To4() == nil {
					klog.Errorf("Invalid ipv4 for service endpoints address %+v, skip", a)
					continue
				}
				backend := svc.Backend{
					IP:       a.IP,
					Port:     p.Port,
					Protocol: p.Protocol,
				}
				if a.NodeName != nil {
					backend.Node = *a.NodeName
				}
				svcPortsMap[p.Name].Spec.Backends = append(svcPortsMap[p.Name].Spec.Backends, backend)
			}
		}
	}

	return svcPortsMap
}

func servicePortListToServicePortMap(servicePortList svc.ServicePortList) map[string]*svc.ServicePort {
	svcPortsMap := make(map[string]*svc.ServicePort)
	for i := range servicePortList.Items {
		portName := servicePortList.Items[i].Spec.PortName
		svcPortsMap[portName] = &servicePortList.Items[i]
	}

	return svcPortsMap
}
