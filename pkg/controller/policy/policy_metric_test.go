package policy

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"

	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	msconst "github.com/everoute/everoute/pkg/constants/ms"
)

func TestDisplayName(t *testing.T) {
	policy := &securityv1alpha1.SecurityPolicy{}
	policy.Name = "tower.sp-policy-a"
	policy.Spec.Logging = &securityv1alpha1.Logging{
		Tags: map[string]string{msconst.LoggingTagPolicyName: "display-policy-a"},
	}

	if got := DisplayName(policy); got != "display-policy-a" {
		t.Fatalf("expected display name from logging tag, got %q", got)
	}

	policy.Spec.Logging.Tags = nil
	if got := DisplayName(policy); got != "tower.sp-policy-a" {
		t.Fatalf("expected display name fallback to policy name, got %q", got)
	}

	if got := DisplayName(nil); got != "" {
		t.Fatalf("expected nil policy display name to be empty, got %q", got)
	}
}

func TestPolicyMetricPredicate(t *testing.T) {
	predicate := policyMetricPredicate()
	oldPolicy := &securityv1alpha1.SecurityPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "policy-a"},
		Spec: securityv1alpha1.SecurityPolicySpec{
			Logging: &securityv1alpha1.Logging{Tags: map[string]string{msconst.LoggingTagPolicyName: "display-a"}},
		},
	}
	sameDisplayNamePolicy := oldPolicy.DeepCopy()
	sameDisplayNamePolicy.Labels = map[string]string{"changed": "true"}
	newDisplayNamePolicy := oldPolicy.DeepCopy()
	newDisplayNamePolicy.Spec.Logging.Tags[msconst.LoggingTagPolicyName] = "display-b"

	if !predicate.Create(event.CreateEvent{Object: oldPolicy}) {
		t.Fatalf("expected create event to reconcile policy metric")
	}
	if predicate.Update(event.UpdateEvent{ObjectOld: oldPolicy, ObjectNew: sameDisplayNamePolicy}) {
		t.Fatalf("expected unchanged display name update event to be skipped")
	}
	if !predicate.Update(event.UpdateEvent{ObjectOld: oldPolicy, ObjectNew: newDisplayNamePolicy}) {
		t.Fatalf("expected display name update event to reconcile policy metric")
	}
	if !predicate.Delete(event.DeleteEvent{Object: oldPolicy}) {
		t.Fatalf("expected delete event to reconcile policy metric")
	}
	if predicate.Generic(event.GenericEvent{Object: oldPolicy}) {
		t.Fatalf("expected generic event to be skipped")
	}
}

func TestPolicyMetricReconcileSetAndDelete(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := securityv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add security scheme: %v", err)
	}

	policy := &securityv1alpha1.SecurityPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "tower-space",
			Name:      "policy-a",
		},
		Spec: securityv1alpha1.SecurityPolicySpec{
			Logging: &securityv1alpha1.Logging{
				Tags: map[string]string{msconst.LoggingTagPolicyName: "display-a"},
			},
		},
	}
	metric := &recordingPolicyMetric{}
	reconciler := &Reconciler{
		Client:       fake.NewClientBuilder().WithScheme(scheme).WithObjects(policy).Build(),
		Scheme:       scheme,
		PolicyMetric: metric,
	}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "tower-space", Name: "policy-a"}}

	if _, err := reconciler.ReconcilePolicyMetric(context.Background(), req); err != nil {
		t.Fatalf("reconcile policy metric: %v", err)
	}
	if metric.setNamespace != "tower-space" || metric.setName != "policy-a" || metric.setDisplayName != "display-a" {
		t.Fatalf("unexpected set metric call: %+v", metric)
	}

	if err := reconciler.Delete(context.Background(), policy); err != nil {
		t.Fatalf("delete policy: %v", err)
	}
	if _, err := reconciler.ReconcilePolicyMetric(context.Background(), req); err != nil {
		t.Fatalf("reconcile deleted policy metric: %v", err)
	}
	if metric.deleteNamespace != "tower-space" || metric.deleteName != "policy-a" {
		t.Fatalf("unexpected delete metric call: %+v", metric)
	}
}

type recordingPolicyMetric struct {
	setNamespace    string
	setName         string
	setDisplayName  string
	deleteNamespace string
	deleteName      string
}

func (m *recordingPolicyMetric) Set(namespace, name, displayName string) {
	m.setNamespace = namespace
	m.setName = name
	m.setDisplayName = displayName
}

func (m *recordingPolicyMetric) Delete(namespace, name string) {
	m.deleteNamespace = namespace
	m.deleteName = name
}
