package computecluster

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	k8sinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	msconst "github.com/everoute/everoute/pkg/constants/ms"
	"github.com/everoute/everoute/plugin/tower/pkg/informer"
	"github.com/everoute/everoute/plugin/tower/pkg/schema"
)

type Controller struct {
	EverouteClusterID  string
	ConfigMapNamespace string

	ctx  context.Context
	name string

	ConfigMapLister         cache.Indexer
	erClusterLister         cache.Indexer
	ConfigMapInformerSynced cache.InformerSynced
	erClusterInformerSynced cache.InformerSynced

	erCli          kubernetes.Interface
	reconcileQueue workqueue.RateLimitingInterface
}

func (c *Controller) Setup(towerFactory informer.SharedInformerFactory, erFactory k8sinformers.SharedInformerFactory, erCli kubernetes.Interface) error {
	c.name = "ComputeClusterController"
	c.erCli = erCli
	c.reconcileQueue = workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	ConfigMapInformer := erFactory.Core().V1().ConfigMaps().Informer()
	_, err := ConfigMapInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.handleConfigMap,
		DeleteFunc: c.handleConfigMap,
		UpdateFunc: c.handleConfigMapUpdate,
	})
	if err != nil {
		klog.Errorf("Failed to add event handler for configMap informer: %s", err)
		return err
	}
	c.ConfigMapLister = ConfigMapInformer.GetIndexer()
	c.ConfigMapInformerSynced = ConfigMapInformer.HasSynced

	erClusterInformer := towerFactory.EverouteCluster()
	_, err = erClusterInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.handleCluster,
		UpdateFunc: c.handleClusterUpdate,
		DeleteFunc: c.handleCluster,
	})
	if err != nil {
		klog.Errorf("Failed to add event handler for networkCluster informer: %s", err)
		return err
	}
	c.erClusterLister = erClusterInformer.GetIndexer()
	c.erClusterInformerSynced = erClusterInformer.HasSynced
	return nil
}

func (c *Controller) Run(ctx context.Context) {
	defer c.reconcileQueue.ShutDown()

	if !cache.WaitForNamedCacheSync(c.name, ctx.Done(),
		c.ConfigMapInformerSynced,
		c.erClusterInformerSynced,
	) {
		return
	}
	c.ctx = ctx

	go wait.Until(informer.ReconcileWorker(c.name, c.reconcileQueue, c.reconcile), time.Second, ctx.Done())

	<-ctx.Done()
}

func (c *Controller) handleConfigMap(obj interface{}) {
	unknow, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		obj = unknow.Obj
	}
	elfCfg := obj.(*corev1.ConfigMap)
	if elfCfg.Name == msconst.ComputeClustersConfigMapName && elfCfg.Namespace == c.ConfigMapNamespace {
		c.reconcileQueue.Add(c.EverouteClusterID)
	}
}

func (c *Controller) handleConfigMapUpdate(oldObj, newObj interface{}) {
	oldCfg := oldObj.(*corev1.ConfigMap)
	newCfg := newObj.(*corev1.ConfigMap)
	if newCfg.Name != msconst.ComputeClustersConfigMapName || newCfg.Namespace != c.ConfigMapNamespace {
		return
	}
	if !configMapDataEqual(oldCfg.Data, newCfg.Data) {
		c.reconcileQueue.Add(c.EverouteClusterID)
		return
	}
	if !hasAssociationAnnotations(oldCfg.Annotations) && hasAssociationAnnotations(newCfg.Annotations) {
		return
	}
	if !associationAnnotationValuesEqual(oldCfg.Annotations, newCfg.Annotations) {
		c.reconcileQueue.Add(c.EverouteClusterID)
	}
}

func (c *Controller) handleCluster(obj interface{}) {
	unknow, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		obj = unknow.Obj
	}
	cluster := obj.(*schema.EverouteCluster)
	if cluster.GetID() != c.EverouteClusterID {
		return
	}
	c.reconcileQueue.Add(c.EverouteClusterID)
}

func (c *Controller) handleClusterUpdate(oldObj, newObj interface{}) {
	oldCluster := oldObj.(*schema.EverouteCluster)
	newCluster := newObj.(*schema.EverouteCluster)

	if newCluster.GetID() != c.EverouteClusterID {
		return
	}

	if reflect.DeepEqual(oldCluster.GetAssociation(), newCluster.GetAssociation()) {
		return
	}
	c.reconcileQueue.Add(c.EverouteClusterID)
}

func (c *Controller) reconcile(id string) error {
	if id != c.EverouteClusterID {
		klog.Warningf("Receive unexpected networkCluster: %s", id)
		return nil
	}

	obj, exists, err := c.ConfigMapLister.GetByKey(c.ConfigMapNamespace + "/" + msconst.ComputeClustersConfigMapName)
	if err != nil {
		klog.Errorf("Failed to get configMap store computeClusters: %s", err)
		return err
	}
	if !exists {
		return c.create()
	}
	return c.update(obj.(*corev1.ConfigMap).DeepCopy())
}

func (c *Controller) create() error {
	obj, exists, err := c.erClusterLister.GetByKey(c.EverouteClusterID)
	if err != nil {
		klog.Errorf("Failed to get networkCluster from cloudPlatform: %s", err)
		return err
	}
	if !exists {
		klog.Errorf("Can't found networkCluster %s, skip create configMap which store computeClusters", c.EverouteClusterID)
		return nil
	}

	ConfigMap := corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: c.ConfigMapNamespace,
			Name:      msconst.ComputeClustersConfigMapName,
		},
	}
	cluster := obj.(*schema.EverouteCluster)
	ConfigMap.Data, err = associationData(cluster.GetAssociation())
	if err != nil {
		return err
	}
	ConfigMap.Annotations = associationAnnotations()
	_, err = c.erCli.CoreV1().ConfigMaps(ConfigMap.Namespace).Create(c.ctx, &ConfigMap, metav1.CreateOptions{})
	if err != nil {
		klog.Errorf("Failed to create configMap with computeClusters %v, err: %s", ConfigMap.Data, err)
		return err
	}
	klog.Infof("Success to create configMap with computeClusters %v", ConfigMap.Data)
	return nil
}

func (c *Controller) update(configMap *corev1.ConfigMap) error {
	obj, exists, err := c.erClusterLister.GetByKey(c.EverouteClusterID)
	if err != nil {
		klog.Errorf("Failed to get networkCluster in cloudPlatform: %s", err)
		return err
	}
	if !exists {
		klog.Errorf("Can't found networkCluster %s, skip update configMap which store computeClusters", c.EverouteClusterID)
		return nil
	}

	cluster := obj.(*schema.EverouteCluster)
	newData, err := associationData(cluster.GetAssociation())
	if err != nil {
		return err
	}
	newAnnotations := associationAnnotations()
	if reflect.DeepEqual(configMap.Data, newData) && hasAssociationAnnotations(configMap.Annotations) {
		return nil
	}

	configMap.Data = newData
	if configMap.Annotations == nil {
		configMap.Annotations = map[string]string{}
	}
	for key, value := range newAnnotations {
		configMap.Annotations[key] = value
	}

	_, err = c.erCli.CoreV1().ConfigMaps(configMap.Namespace).Update(c.ctx, configMap, metav1.UpdateOptions{})
	if err != nil {
		klog.Errorf("Failed to update configMap with computeClusters %v, err: %s", configMap.Data, err)
		return err
	}
	klog.Infof("Success to update configMap with computeClusters %v", configMap.Data)
	return nil
}

func associationData(association map[string]sets.Set[string]) (map[string]string, error) {
	data := make(map[string]string, len(association))
	for clusterID, vdsSet := range association {
		vdsIDs := vdsSet.UnsortedList()
		sort.Strings(vdsIDs)
		raw, err := json.Marshal(vdsIDs)
		if err != nil {
			return nil, err
		}
		data[clusterID] = string(raw)
	}
	return data, nil
}

func associationAnnotations() map[string]string {
	return map[string]string{
		msconst.AssociationSyncCompletedAnnotation: "true",
		msconst.AssociationFormatVersionAnnotation: msconst.AssociationFormatVersionV2,
	}
}

func hasAssociationAnnotations(annotations map[string]string) bool {
	return annotations[msconst.AssociationSyncCompletedAnnotation] == "true" &&
		annotations[msconst.AssociationFormatVersionAnnotation] == msconst.AssociationFormatVersionV2
}

func associationAnnotationValuesEqual(a, b map[string]string) bool {
	return a[msconst.AssociationSyncCompletedAnnotation] == b[msconst.AssociationSyncCompletedAnnotation] &&
		a[msconst.AssociationFormatVersionAnnotation] == b[msconst.AssociationFormatVersionAnnotation]
}

func configMapDataEqual(a, b map[string]string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}
