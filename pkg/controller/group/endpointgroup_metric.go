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

package group

import (
	"context"
	"fmt"
	"sort"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"

	groupv1alpha1 "github.com/everoute/everoute/pkg/apis/group/v1alpha1"
	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	msconst "github.com/everoute/everoute/pkg/constants/ms"
	"github.com/everoute/everoute/pkg/labels"
	"github.com/everoute/everoute/pkg/metrics"
)

func (r *Reconciler) recordEndpointGroupInfo(ctx context.Context, group *groupv1alpha1.EndpointGroup) {
	if r == nil || r.EndpointGroupMetric == nil || group == nil {
		return
	}
	targetType := endpointGroupTargetType(&group.Spec)
	r.EndpointGroupMetric.Set(group.Name, targetType, r.endpointGroupTargetDisplay(ctx, &group.Spec, targetType))
}

func endpointGroupTargetType(spec *groupv1alpha1.EndpointGroupSpec) string {
	if spec == nil {
		return metrics.EndpointGroupTargetTypeUnknown
	}
	if selectorHasPodClusterLabels(spec.EndpointSelector) {
		return metrics.EndpointGroupTargetTypePod
	}
	if spec.Endpoint != nil {
		return metrics.EndpointGroupTargetTypeVNIC
	}
	if spec.EndpointSelector != nil {
		return metrics.EndpointGroupTargetTypeVMLabel
	}
	return metrics.EndpointGroupTargetTypeUnknown
}

func selectorHasPodClusterLabels(selector *labels.Selector) bool {
	if selector == nil {
		return false
	}
	_, hasKSCName := selector.LabelSelector.MatchLabels[msconst.SKSLabelKeyClusterName]
	_, hasKSCNamespace := selector.LabelSelector.MatchLabels[msconst.SKSLabelKeyClusterNamespace]
	return hasKSCName && hasKSCNamespace
}

func (r *Reconciler) endpointGroupTargetDisplay(ctx context.Context, spec *groupv1alpha1.EndpointGroupSpec, targetType string) string {
	if spec == nil {
		return ""
	}

	parts := make([]string, 0, 3)
	switch targetType {
	case metrics.EndpointGroupTargetTypeVNIC:
		return r.vnicTargetDisplay(ctx, spec.Endpoint)
	case metrics.EndpointGroupTargetTypeVMLabel:
		return selectorDisplay(spec.EndpointSelector)
	case metrics.EndpointGroupTargetTypePod:
		parts = append(parts, "selector="+selectorDisplay(spec.EndpointSelector))
	default:
		parts = append(parts, "unknown")
	}

	if spec.Namespace != nil && *spec.Namespace != "" {
		parts = append(parts, "spec.namespace="+*spec.Namespace)
	}
	if spec.NamespaceSelector != nil {
		parts = append(parts, "namespaceSelector="+labelSelectorDisplay(spec.NamespaceSelector))
	}
	return strings.Join(parts, ", ")
}

func (r *Reconciler) vnicTargetDisplay(ctx context.Context, endpointRef *securityv1alpha1.NamespacedName) string {
	if endpointRef == nil {
		return ""
	}
	if r != nil && r.Client != nil {
		endpoint := securityv1alpha1.Endpoint{}
		err := r.Get(ctx, k8stypes.NamespacedName{Name: endpointRef.Name, Namespace: endpointRef.Namespace}, &endpoint)
		if err != nil && !apierrors.IsNotFound(err) {
			klog.Errorf("failed to get endpoint %s/%s for endpointgroup metric: %s", endpointRef.Namespace, endpointRef.Name, err)
		}
		if err == nil && endpoint.Spec.VMID != "" {
			return endpoint.Spec.VMID
		}
	}
	return endpointRef.Namespace + "/" + endpointRef.Name
}

func selectorDisplay(selector *labels.Selector) string {
	if selector == nil {
		return "<nil>"
	}
	if selector.MatchNothing {
		return "matchNothing=true"
	}

	parts := labelSelectorParts(&selector.LabelSelector)
	extendKeys := make([]string, 0, len(selector.ExtendMatchLabels))
	for key := range selector.ExtendMatchLabels {
		extendKeys = append(extendKeys, key)
	}
	sort.Strings(extendKeys)
	for _, key := range extendKeys {
		values := append([]string{}, selector.ExtendMatchLabels[key]...)
		sort.Strings(values)
		parts = append(parts, fmt.Sprintf("%s in (%s)", key, strings.Join(values, ",")))
	}
	if len(parts) == 0 {
		return "<all>"
	}
	return strings.Join(parts, ",")
}

func labelSelectorDisplay(selector *metav1.LabelSelector) string {
	if selector == nil {
		return "<nil>"
	}
	parts := labelSelectorParts(selector)
	if len(parts) == 0 {
		return "<all>"
	}
	return strings.Join(parts, ",")
}

func labelSelectorParts(selector *metav1.LabelSelector) []string {
	parts := make([]string, 0, len(selector.MatchLabels)+len(selector.MatchExpressions))
	keys := make([]string, 0, len(selector.MatchLabels))
	for key := range selector.MatchLabels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", key, selector.MatchLabels[key]))
	}

	expressions := append([]metav1.LabelSelectorRequirement{}, selector.MatchExpressions...)
	sort.Slice(expressions, func(i, j int) bool {
		if expressions[i].Key != expressions[j].Key {
			return expressions[i].Key < expressions[j].Key
		}
		return string(expressions[i].Operator) < string(expressions[j].Operator)
	})
	for _, expr := range expressions {
		values := append([]string{}, expr.Values...)
		sort.Strings(values)
		if len(values) == 0 {
			parts = append(parts, fmt.Sprintf("%s %s", expr.Key, expr.Operator))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s %s (%s)", expr.Key, expr.Operator, strings.Join(values, ",")))
	}
	return parts
}
