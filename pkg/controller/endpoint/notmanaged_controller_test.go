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

package endpoint

import (
	"context"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"

	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	clientsetscheme "github.com/everoute/everoute/pkg/client/clientset_generated/clientset/scheme"
	msconst "github.com/everoute/everoute/pkg/constants/ms"
)

var _ = Describe("notManaged controller", func() {
	ctx := context.Background()
	namespace := "tower-space"

	type testEndpoint struct {
		name           string
		vdsID          string
		notManaged     bool
		wantNotManaged bool
	}

	newEndpoint := func(ep testEndpoint) *securityv1alpha1.Endpoint {
		labels := map[string]string{}
		if ep.vdsID != "" {
			labels[msconst.EndpointLabelKeyVDSID] = ep.vdsID
		}
		return &securityv1alpha1.Endpoint{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ep.name,
				Namespace: "default",
				Labels:    labels,
			},
			Spec:   securityv1alpha1.EndpointSpec{VDSID: ep.vdsID},
			Status: securityv1alpha1.EndpointStatus{NotManaged: ep.notManaged},
		}
	}

	reconcileQueuedEndpoints := func(reconciler *NotManagedReconciler) {
		for len(reconciler.EndpointQueue) > 0 {
			genericEvent := <-reconciler.EndpointQueue
			_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: k8stypes.NamespacedName{
				Namespace: genericEvent.Object.GetNamespace(),
				Name:      genericEvent.Object.GetName(),
			}})
			Expect(err).ShouldNot(HaveOccurred())
		}
	}

	expectEndpointNotManaged := func(k8sClient client.Client, ep testEndpoint) {
		got := securityv1alpha1.Endpoint{}
		Expect(k8sClient.Get(ctx, k8stypes.NamespacedName{Name: ep.name, Namespace: "default"}, &got)).Should(Succeed())
		Expect(got.Status.NotManaged).Should(Equal(ep.wantNotManaged), "endpoint %s", ep.name)
	}

	testScheme := func() *runtime.Scheme {
		scheme := runtime.NewScheme()
		Expect(clientsetscheme.AddToScheme(scheme)).Should(Succeed())
		Expect(corev1.AddToScheme(scheme)).Should(Succeed())
		return scheme
	}

	It("reconciles all endpoints when association configmap becomes prepared", func() {
		endpoints := []testEndpoint{
			{name: "prepared-no-vds", wantNotManaged: false},
			{name: "prepared-managed-vds", vdsID: "vds-1", notManaged: true, wantNotManaged: false},
			{name: "prepared-unmanaged-vds", vdsID: "vds-2", wantNotManaged: true},
		}

		objects := []client.Object{
			preparedAssociationConfigMap(namespace, map[string]string{"cluster-1": `["vds-1"]`}),
		}
		for _, ep := range endpoints {
			objects = append(objects, newEndpoint(ep))
		}
		k8sClient := fake.NewClientBuilder().
			WithScheme(testScheme()).
			WithStatusSubresource(&securityv1alpha1.Endpoint{}).
			WithObjects(objects...).
			Build()
		reconciler := newTestNotManagedReconciler(k8sClient, namespace)

		_, err := reconciler.ReconcileConfigMap(ctx, ctrl.Request{NamespacedName: k8stypes.NamespacedName{
			Name:      msconst.ComputeClustersConfigMapName,
			Namespace: namespace,
		}})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(reconciler.EndpointQueue).Should(HaveLen(len(endpoints)))

		reconcileQueuedEndpoints(reconciler)
		for _, ep := range endpoints {
			expectEndpointNotManaged(k8sClient, ep)
		}
	})

	It("reconciles endpoints in changed vdses when association configmap changes", func() {
		endpoints := []testEndpoint{
			{name: "changed-managed-vds", vdsID: "vds-1", wantNotManaged: false},
			{name: "changed-new-managed-vds", vdsID: "vds-2", notManaged: true, wantNotManaged: false},
			{name: "changed-no-vds", wantNotManaged: false},
		}

		configMap := preparedAssociationConfigMap(namespace, map[string]string{"cluster-1": `["vds-1","vds-2"]`})
		objects := []client.Object{configMap}
		for _, ep := range endpoints {
			objects = append(objects, newEndpoint(ep))
		}
		k8sClient := fake.NewClientBuilder().
			WithScheme(testScheme()).
			WithStatusSubresource(&securityv1alpha1.Endpoint{}).
			WithObjects(objects...).
			Build()
		reconciler := newTestNotManagedReconciler(k8sClient, namespace)
		reconciler.updateConfigMapCache(true, sets.New("vds-1"))

		_, err := reconciler.ReconcileConfigMap(ctx, ctrl.Request{NamespacedName: k8stypes.NamespacedName{
			Name:      msconst.ComputeClustersConfigMapName,
			Namespace: namespace,
		}})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(reconciler.EndpointQueue).Should(HaveLen(1))

		reconcileQueuedEndpoints(reconciler)
		for _, ep := range endpoints {
			expectEndpointNotManaged(k8sClient, ep)
		}
	})
})

func TestManagedVDSesFromConfigMap(t *testing.T) {
	tests := []struct {
		name         string
		configMap    *corev1.ConfigMap
		wantPrepared bool
		wantVDSes    sets.Set[string]
		wantErr      bool
	}{
		{
			name: "not prepared",
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: msconst.ComputeClustersConfigMapName},
				Data:       map[string]string{"cluster-1": `["vds-1"]`},
			},
			wantPrepared: false,
			wantVDSes:    sets.New[string](),
		},
		{
			name: "prepared v2",
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name: msconst.ComputeClustersConfigMapName,
					Annotations: map[string]string{
						msconst.AssociationSyncCompletedAnnotation: "true",
						msconst.AssociationFormatVersionAnnotation: msconst.AssociationFormatVersionV2,
					},
				},
				Data: map[string]string{
					"cluster-1": `["vds-1","vds-2"]`,
					"cluster-2": `["vds-2","vds-3"]`,
				},
			},
			wantPrepared: true,
			wantVDSes:    sets.New("vds-1", "vds-2", "vds-3"),
		},
		{
			name: "invalid vds list",
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name: msconst.ComputeClustersConfigMapName,
					Annotations: map[string]string{
						msconst.AssociationSyncCompletedAnnotation: "true",
						msconst.AssociationFormatVersionAnnotation: msconst.AssociationFormatVersionV2,
					},
				},
				Data: map[string]string{"cluster-1": `invalid`},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPrepared, gotVDSes, err := managedVDSesFromConfigMap(tt.configMap)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotPrepared != tt.wantPrepared {
				t.Fatalf("unexpected prepared, got %v want %v", gotPrepared, tt.wantPrepared)
			}
			if !gotVDSes.Equal(tt.wantVDSes) {
				t.Fatalf("unexpected managed vdses, got %v want %v", gotVDSes, tt.wantVDSes)
			}
		})
	}
}

func TestNotManagedReconcileEndpoint(t *testing.T) {
	ctx := context.Background()
	associationConfigMap := preparedAssociationConfigMap("tower-space", map[string]string{"cluster-1": `["vds-1"]`})
	tests := []struct {
		name           string
		endpoint       *securityv1alpha1.Endpoint
		wantNotManaged bool
	}{
		{
			name: "endpoint without vds is managed",
			endpoint: &securityv1alpha1.Endpoint{
				ObjectMeta: metav1.ObjectMeta{Name: "ep-1", Namespace: "default"},
			},
			wantNotManaged: false,
		},
		{
			name: "endpoint in managed vds is managed",
			endpoint: &securityv1alpha1.Endpoint{
				ObjectMeta: metav1.ObjectMeta{Name: "ep-2", Namespace: "default"},
				Spec:       securityv1alpha1.EndpointSpec{VDSID: "vds-1"},
				Status:     securityv1alpha1.EndpointStatus{NotManaged: true},
			},
			wantNotManaged: false,
		},
		{
			name: "endpoint outside managed vds is notManaged",
			endpoint: &securityv1alpha1.Endpoint{
				ObjectMeta: metav1.ObjectMeta{Name: "ep-3", Namespace: "default"},
				Spec:       securityv1alpha1.EndpointSpec{VDSID: "vds-2"},
			},
			wantNotManaged: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8sClient := fake.NewClientBuilder().
				WithScheme(testScheme(t)).
				WithStatusSubresource(&securityv1alpha1.Endpoint{}).
				WithObjects(tt.endpoint.DeepCopy(), associationConfigMap.DeepCopy()).
				Build()
			reconciler := newTestNotManagedReconciler(k8sClient, "tower-space")

			_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: k8stypes.NamespacedName{
				Name:      tt.endpoint.Name,
				Namespace: tt.endpoint.Namespace,
			}})
			if err != nil {
				t.Fatalf("reconcile endpoint: %v", err)
			}

			got := securityv1alpha1.Endpoint{}
			if err := k8sClient.Get(ctx, k8stypes.NamespacedName{Name: tt.endpoint.Name, Namespace: tt.endpoint.Namespace}, &got); err != nil {
				t.Fatalf("get endpoint: %v", err)
			}
			if got.Status.NotManaged != tt.wantNotManaged {
				t.Fatalf("unexpected notManaged, got %v want %v", got.Status.NotManaged, tt.wantNotManaged)
			}
		})
	}
}

func TestNotManagedReconcileEndpointSkipBeforeAssociationPrepared(t *testing.T) {
	ctx := context.Background()
	endpoint := &securityv1alpha1.Endpoint{
		ObjectMeta: metav1.ObjectMeta{Name: "ep", Namespace: "default"},
		Spec:       securityv1alpha1.EndpointSpec{VDSID: "vds-2"},
	}
	k8sClient := fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithStatusSubresource(&securityv1alpha1.Endpoint{}).
		WithObjects(endpoint).
		Build()
	reconciler := newTestNotManagedReconciler(k8sClient, "tower-space")

	_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: k8stypes.NamespacedName{
		Name:      endpoint.Name,
		Namespace: endpoint.Namespace,
	}})
	if err != nil {
		t.Fatalf("reconcile endpoint: %v", err)
	}

	got := securityv1alpha1.Endpoint{}
	if err := k8sClient.Get(ctx, k8stypes.NamespacedName{Name: endpoint.Name, Namespace: endpoint.Namespace}, &got); err != nil {
		t.Fatalf("get endpoint: %v", err)
	}
	if got.Status.NotManaged {
		t.Fatalf("endpoint should not be marked notManaged before association configmap prepared")
	}
}

func TestNotManagedReconcileConfigMapEnqueuesEndpoints(t *testing.T) {
	ctx := context.Background()
	managedEndpoint := &securityv1alpha1.Endpoint{
		ObjectMeta: metav1.ObjectMeta{Name: "managed", Namespace: "default"},
		Spec:       securityv1alpha1.EndpointSpec{VDSID: "vds-1"},
		Status:     securityv1alpha1.EndpointStatus{NotManaged: true},
	}
	notManagedEndpoint := &securityv1alpha1.Endpoint{
		ObjectMeta: metav1.ObjectMeta{Name: "not-managed", Namespace: "default"},
		Spec:       securityv1alpha1.EndpointSpec{VDSID: "vds-2"},
	}
	associationConfigMap := preparedAssociationConfigMap("tower-space", map[string]string{"cluster-1": `["vds-1"]`})
	k8sClient := fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithStatusSubresource(&securityv1alpha1.Endpoint{}).
		WithObjects(managedEndpoint, notManagedEndpoint, associationConfigMap).
		Build()
	reconciler := newTestNotManagedReconciler(k8sClient, "tower-space")

	_, err := reconciler.ReconcileConfigMap(ctx, ctrl.Request{NamespacedName: k8stypes.NamespacedName{
		Name:      msconst.ComputeClustersConfigMapName,
		Namespace: "tower-space",
	}})
	if err != nil {
		t.Fatalf("reconcile configmap: %v", err)
	}

	if len(reconciler.EndpointQueue) != 2 {
		t.Fatalf("unexpected endpoint queue length, got %d want 2", len(reconciler.EndpointQueue))
	}
	gotRequests := sets.New[string]()
	for len(reconciler.EndpointQueue) > 0 {
		event := <-reconciler.EndpointQueue
		gotRequests.Insert(event.Object.GetNamespace() + "/" + event.Object.GetName())
	}
	wantRequests := sets.New("default/managed", "default/not-managed")
	if !gotRequests.Equal(wantRequests) {
		t.Fatalf("unexpected endpoint requests, got %v want %v", gotRequests.UnsortedList(), wantRequests.UnsortedList())
	}
}

func TestNotManagedReconcileConfigMapEnqueuesChangedVDSEndpoints(t *testing.T) {
	ctx := context.Background()
	changedEndpoint := &securityv1alpha1.Endpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "changed",
			Namespace: "default",
			Labels:    map[string]string{msconst.EndpointLabelKeyVDSID: "vds-2"},
		},
		Spec: securityv1alpha1.EndpointSpec{VDSID: "vds-2"},
	}
	unchangedEndpoint := &securityv1alpha1.Endpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "unchanged",
			Namespace: "default",
			Labels:    map[string]string{msconst.EndpointLabelKeyVDSID: "vds-1"},
		},
		Spec: securityv1alpha1.EndpointSpec{VDSID: "vds-1"},
	}
	associationConfigMap := preparedAssociationConfigMap("tower-space", map[string]string{"cluster-1": `["vds-1","vds-2"]`})
	k8sClient := fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithObjects(changedEndpoint, unchangedEndpoint, associationConfigMap).
		Build()
	reconciler := newTestNotManagedReconciler(k8sClient, "tower-space")
	reconciler.updateConfigMapCache(true, sets.New("vds-1"))

	_, err := reconciler.ReconcileConfigMap(ctx, ctrl.Request{NamespacedName: k8stypes.NamespacedName{
		Name:      msconst.ComputeClustersConfigMapName,
		Namespace: "tower-space",
	}})
	if err != nil {
		t.Fatalf("reconcile configmap: %v", err)
	}

	if len(reconciler.EndpointQueue) != 1 {
		t.Fatalf("unexpected endpoint queue length, got %d want 1", len(reconciler.EndpointQueue))
	}
	event := <-reconciler.EndpointQueue
	if event.Object.GetNamespace() != changedEndpoint.Namespace || event.Object.GetName() != changedEndpoint.Name {
		t.Fatalf("unexpected queued endpoint %s/%s", event.Object.GetNamespace(), event.Object.GetName())
	}
}

func TestNotManagedConfigMapUpdatePredicate(t *testing.T) {
	reconciler := newTestNotManagedReconciler(nil, "tower-space")
	oldConfigMap := preparedAssociationConfigMap("tower-space", map[string]string{"cluster-1": `["vds-1"]`})
	newConfigMap := preparedAssociationConfigMap("tower-space", map[string]string{"cluster-1": `["vds-1","vds-2"]`})

	p := reconciler.configMapPredicate()
	if !p.Update(event.UpdateEvent{ObjectOld: oldConfigMap, ObjectNew: newConfigMap}) {
		t.Fatalf("vds set change should pass configmap update predicate")
	}

	if p.Update(event.UpdateEvent{ObjectOld: oldConfigMap, ObjectNew: oldConfigMap.DeepCopy()}) {
		t.Fatalf("same vds set should not pass configmap update predicate")
	}
}

func TestEndpointVDSIDChangedPredicate(t *testing.T) {
	p := endpointVDSIDChangedPredicate()
	oldEndpoint := &securityv1alpha1.Endpoint{Spec: securityv1alpha1.EndpointSpec{VDSID: "vds-1"}}
	sameEndpoint := &securityv1alpha1.Endpoint{Spec: securityv1alpha1.EndpointSpec{VDSID: "vds-1"}}
	changedEndpoint := &securityv1alpha1.Endpoint{Spec: securityv1alpha1.EndpointSpec{VDSID: "vds-2"}}

	if !p.Create(event.CreateEvent{Object: oldEndpoint}) {
		t.Fatalf("create event should be enqueued")
	}
	if p.Delete(event.DeleteEvent{Object: oldEndpoint}) {
		t.Fatalf("delete event should not be enqueued")
	}
	if !p.Generic(event.GenericEvent{Object: oldEndpoint}) {
		t.Fatalf("generic event should be enqueued")
	}
	if p.Update(event.UpdateEvent{ObjectOld: oldEndpoint, ObjectNew: sameEndpoint}) {
		t.Fatalf("same vdsID update should not be enqueued")
	}
	if !p.Update(event.UpdateEvent{ObjectOld: oldEndpoint, ObjectNew: changedEndpoint}) {
		t.Fatalf("changed vdsID update should be enqueued")
	}
}

func preparedAssociationConfigMap(namespace string, data map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      msconst.ComputeClustersConfigMapName,
			Namespace: namespace,
			Annotations: map[string]string{
				msconst.AssociationSyncCompletedAnnotation: "true",
				msconst.AssociationFormatVersionAnnotation: msconst.AssociationFormatVersionV2,
			},
		},
		Data: data,
	}
}

func newTestNotManagedReconciler(k8sClient client.Client, namespace string) *NotManagedReconciler {
	return &NotManagedReconciler{
		Client:             k8sClient,
		ConfigMapNamespace: namespace,
		ConfigMapName:      msconst.ComputeClustersConfigMapName,
		EndpointQueue:      make(chan event.GenericEvent, 10),
	}
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientsetscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("add everoute scheme: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add core scheme: %v", err)
	}
	return scheme
}
