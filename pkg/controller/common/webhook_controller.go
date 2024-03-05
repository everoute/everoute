/*
Copyright 2021 The Everoute Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package common

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/cenkalti/backoff"
	admv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/everoute/everoute/pkg/constants"
)

// WebhookReconciler watch webhook
type WebhookReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Namespace string
}

// Reconcile receive webhook from work queue
func (r *WebhookReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	klog.Infof("WebhookReconciler received webhook %s reconcile", req.NamespacedName)

	secret := &corev1.Secret{}
	secretReq := types.NamespacedName{
		Name:      constants.EverouteSecretName,
		Namespace: r.Namespace,
	}
	if err := r.Get(ctx, secretReq, secret); err != nil {
		klog.Fatalf("could not found secret %s/%s, err: %s", secretReq.Namespace, secretReq.Name, err)
	}

	webhook := &admv1.ValidatingWebhookConfiguration{}
	if err := r.Get(ctx, req.NamespacedName, webhook); err != nil {
		klog.Fatalf("could not found secret %s/%s, err: %s", secretReq.Namespace, secretReq.Name, err)
	}

	// update webhook
	webhookObj := &admv1.ValidatingWebhookConfiguration{}
	if err := backoff.Retry(func() error {
		if err := r.Get(ctx, req.NamespacedName, webhookObj); err != nil {
			return err
		}
		if bytes.Equal(webhookObj.Webhooks[0].ClientConfig.CABundle, secret.Data["ca.crt"]) {
			return nil
		}
		webhookObj.Webhooks[0].ClientConfig.CABundle = append([]byte{}, secret.Data["ca.crt"]...)
		return r.Update(ctx, webhookObj)
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 10)); err != nil {
		klog.Fatalf("fail to update webhook after 10 tries. err: %s", err)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager create and add Webhook Controller to the manager.
func (r *WebhookReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if mgr == nil {
		return fmt.Errorf("can't setup with nil manager")
	}
	if r.Namespace == "" {
		return fmt.Errorf("must set namespace")
	}

	c, err := controller.New("webhook-controller", mgr, controller.Options{
		MaxConcurrentReconciles: constants.DefaultMaxConcurrentReconciles,
		Reconciler:              r,
	})
	if err != nil {
		return err
	}

	return c.Watch(source.Kind(mgr.GetCache(), &admv1.ValidatingWebhookConfiguration{}), &handler.Funcs{
		CreateFunc: func(_ context.Context, e event.CreateEvent, q workqueue.RateLimitingInterface) {
			if e.Object == nil {
				klog.Errorf("receive create event with no object %v", e)
				return
			}
			if e.Object.GetName() == constants.EverouteWebhookName || e.Object.GetName() == constants.EverouteIPAMWebhookName {
				q.Add(ctrl.Request{NamespacedName: types.NamespacedName{
					Name: e.Object.GetName(),
				}})
			}
		},
		UpdateFunc: func(_ context.Context, e event.UpdateEvent, q workqueue.RateLimitingInterface) {
			newWebhook := e.ObjectNew.(*admv1.ValidatingWebhookConfiguration)
			if newWebhook.GetName() == constants.EverouteWebhookName || newWebhook.GetName() == constants.EverouteIPAMWebhookName {
				q.Add(ctrl.Request{NamespacedName: types.NamespacedName{
					Name: newWebhook.GetName(),
				}})
			}
		},
	})
}
