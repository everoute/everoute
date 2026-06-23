package group

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	groupv1alpha1 "github.com/everoute/everoute/pkg/apis/group/v1alpha1"
	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	msconst "github.com/everoute/everoute/pkg/constants/ms"
	"github.com/everoute/everoute/pkg/labels"
	"github.com/everoute/everoute/pkg/metrics"
)

func TestEndpointGroupTargetType(t *testing.T) {
	tests := []struct {
		name string
		spec groupv1alpha1.EndpointGroupSpec
		want string
	}{
		{
			name: "pod selector",
			spec: groupv1alpha1.EndpointGroupSpec{
				EndpointSelector: &labels.Selector{LabelSelector: metav1.LabelSelector{MatchLabels: map[string]string{
					msconst.SKSLabelKeyClusterName:      "cluster-a",
					msconst.SKSLabelKeyClusterNamespace: "default",
				}}},
			},
			want: metrics.EndpointGroupTargetTypePod,
		},
		{
			name: "vm endpoint",
			spec: groupv1alpha1.EndpointGroupSpec{
				Endpoint: &securityv1alpha1.NamespacedName{Namespace: "tower-space", Name: "vnic-a"},
			},
			want: metrics.EndpointGroupTargetTypeVM,
		},
		{
			name: "vm label selector",
			spec: groupv1alpha1.EndpointGroupSpec{
				EndpointSelector: &labels.Selector{LabelSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "db"}}},
			},
			want: metrics.EndpointGroupTargetTypeVMLabel,
		},
		{
			name: "unknown",
			spec: groupv1alpha1.EndpointGroupSpec{},
			want: metrics.EndpointGroupTargetTypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := endpointGroupTargetType(&tt.spec); got != tt.want {
				t.Fatalf("expected target type %q, got %q", tt.want, got)
			}
		})
	}
}

func TestEndpointGroupTargetDisplayStable(t *testing.T) {
	spec := &groupv1alpha1.EndpointGroupSpec{
		EndpointSelector: &labels.Selector{
			LabelSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"z": "1",
					"a": "2",
				},
			},
			ExtendMatchLabels: map[string][]string{
				"extend": {"b", "a"},
			},
		},
	}

	want := "a=2,z=1,extend in (a,b)"
	if got := (&Reconciler{}).endpointGroupTargetDisplay(context.Background(), spec, metrics.EndpointGroupTargetTypeVMLabel); got != want {
		t.Fatalf("expected display %q, got %q", want, got)
	}
}

func TestEndpointGroupVMTargetDisplay(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := securityv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("add security scheme: %s", err)
	}

	reconciler := &Reconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(&securityv1alpha1.Endpoint{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "tower-space",
			Name:      "endpoint-a",
		},
		Spec: securityv1alpha1.EndpointSpec{
			VMID: "vm-a",
		},
	}).Build()}

	spec := &groupv1alpha1.EndpointGroupSpec{Endpoint: &securityv1alpha1.NamespacedName{
		Namespace: "tower-space",
		Name:      "endpoint-a",
	}}

	if got := reconciler.endpointGroupTargetDisplay(context.Background(), spec, metrics.EndpointGroupTargetTypeVM); got != "vm-a" {
		t.Fatalf("expected vm id display %q, got %q", "vm-a", got)
	}

	spec.Endpoint = &securityv1alpha1.NamespacedName{Namespace: "tower-space", Name: "endpoint-missing"}
	if got := reconciler.endpointGroupTargetDisplay(context.Background(), spec, metrics.EndpointGroupTargetTypeVM); got != "endpoint-missing" {
		t.Fatalf("expected endpoint id fallback %q, got %q", "endpoint-missing", got)
	}

	spec.Endpoint = &securityv1alpha1.NamespacedName{Namespace: "tower-space", Name: "endpoint-a"}
	endpoint := securityv1alpha1.Endpoint{}
	if err := reconciler.Get(context.Background(), k8stypes.NamespacedName{Namespace: "tower-space", Name: "endpoint-a"}, &endpoint); err != nil {
		t.Fatalf("get endpoint: %s", err)
	}
	endpoint.Spec.VMID = ""
	if err := reconciler.Update(context.Background(), &endpoint); err != nil {
		t.Fatalf("update endpoint: %s", err)
	}
	if got := reconciler.endpointGroupTargetDisplay(context.Background(), spec, metrics.EndpointGroupTargetTypeVM); got != "endpoint-a" {
		t.Fatalf("expected endpoint id fallback %q, got %q", "endpoint-a", got)
	}
}
