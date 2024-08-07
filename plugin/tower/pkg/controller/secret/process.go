package secret

import (
	"bytes"
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"

	msconst "github.com/everoute/everoute/pkg/constants/ms"
	ersource "github.com/everoute/everoute/pkg/source"
)

type Process struct {
	// Namespace, the everoute namespace that k8s-mgmt-kubeconfig secret in
	Namespace string
	ERCli     client.Client
	TowerCli  client.Client
}

func (p *Process) SetupWithManager(mgr ctrl.Manager, queue chan event.GenericEvent, syncCaches ...ersource.SyncCache) error {
	if mgr == nil {
		klog.Error("Can't setup secret-process controller with nil manager")
		return fmt.Errorf("can't setup secret-process controller with nil manager")
	}
	if queue == nil {
		klog.Error("Can't setup secret-process controller with param queue is nil")
		return fmt.Errorf("param queue is nil")
	}
	if p.ERCli == nil || p.TowerCli == nil {
		klog.Errorf("Can't setup secret-process controller, Invalid param client, networkCluster cli %v, cloudPlatform cli %v", p.ERCli, p.TowerCli)
		return fmt.Errorf("invalid param")
	}
	cm, err := controller.New("secret-process", mgr, controller.Options{
		Reconciler: p,
	})
	if err != nil {
		klog.Errorf("Failed to new secret-process controller: %s", err)
		return err
	}
	err = cm.Watch(&ersource.SyncingChannel{
		Name:       "syncSKSKubeconfig",
		Channel:    source.Channel{Source: queue},
		SyncCaches: syncCaches,
	}, &handler.EnqueueRequestForObject{})
	if err != nil {
		klog.Errorf("Failed to watch channel for secret-process controller: %s", err)
	}
	return err
}

func (p *Process) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)
	log.Info("Reconcile start")
	defer log.Info("Reconcile end")

	exp := types.NamespacedName{
		Namespace: msconst.K8sMPKubeconfigNsInCloudPlatform,
		Name:      msconst.K8sMPKubeconfigNameInCloudPlatform,
	}
	if req.NamespacedName != exp {
		log.Error(nil, "Unexpect cloudPlatform secret, skip process")
		return ctrl.Result{}, nil
	}
	towerObj := corev1.Secret{}
	if err := p.TowerCli.Get(ctx, req.NamespacedName, &towerObj); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, p.delete(ctx)
		}
		log.Error(err, "Failed to get k8sMgmtPlatform kubeconfig from cloudPlatform")
		return ctrl.Result{}, err
	}
	if towerObj.ObjectMeta.DeletionTimestamp != nil {
		return ctrl.Result{}, p.delete(ctx)
	}

	if towerObj.Data["value"] == nil {
		e := fmt.Errorf("k8sMgmtPlatform kubeconfig in cloudPlatform is invalid")
		log.Error(nil, "k8sMgmtPlatform kubeconfig in cloudPlatform value is nil")
		return ctrl.Result{}, e
	}
	return ctrl.Result{}, p.createOrUpdate(ctx, &towerObj)
}

func (p *Process) delete(ctx context.Context) error {
	log := ctrl.LoggerFrom(ctx)
	erObj := corev1.Secret{}
	key := types.NamespacedName{
		Namespace: p.Namespace,
		Name:      msconst.K8sMPKubeconfigName,
	}
	log = log.WithValues("erSecret", key)
	if err := p.ERCli.Get(ctx, key, &erObj); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("K8sMgmtPlatform kubeconfig has been deleted in networkCluster")
			return nil
		}
		log.Error(err, "Failed to get k8sMgmtPlatform kubeconfig in networkCluster")
		return err
	}

	if err := p.ERCli.Delete(ctx, &erObj); err != nil {
		log.Error(err, "failed to delete k8sMgmtPlatform kubeconfig in networkCluster")
		return err
	}
	log.Info("Success to delete k8sMgmtPlatform kubeconfig in networkCluster")
	return nil
}

func (p *Process) createOrUpdate(ctx context.Context, towerObj *corev1.Secret) error {
	key := types.NamespacedName{
		Namespace: p.Namespace,
		Name:      msconst.K8sMPKubeconfigName,
	}

	log := ctrl.LoggerFrom(ctx)
	log = log.WithValues("erSecret", key)
	ctrl.LoggerInto(ctx, log)

	erObj := corev1.Secret{}
	if err := p.ERCli.Get(ctx, key, &erObj); err != nil {
		if apierrors.IsNotFound(err) {
			return p.create(ctx, towerObj)
		}
		log.Error(err, "Failed to get k8sMgmtPlatform kubeconfig in networkCluster")
		return err
	}
	if bytes.Equal(erObj.Data["value"], towerObj.Data["value"]) {
		return nil
	}
	erObj.Data["value"] = bytes.Clone(towerObj.Data["value"])
	if err := p.ERCli.Update(ctx, &erObj); err != nil {
		log.Error(err, "Failed to update k8sMgmtPlatform kubeconfig to networkCluster")
		return err
	}
	log.Info("Success to update k8sMgmtPlatform kubeconfig to networkCluster")
	return nil
}

func (p *Process) create(ctx context.Context, towerObj *corev1.Secret) error {
	log := ctrl.LoggerFrom(ctx)
	erObj := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: p.Namespace,
			Name:      msconst.K8sMPKubeconfigName,
		},
		Data: make(map[string][]byte, 1),
	}
	erObj.Data["value"] = bytes.Clone(towerObj.Data["value"])

	if err := p.ERCli.Create(ctx, &erObj); err != nil {
		log.Error(err, "Failed to create k8sMgmtPlatform kubeconfig to networkCluster")
		return err
	}
	log.Info("Success create k8sMgmtPlatform kubeconfig to networkCluster")
	return nil
}
