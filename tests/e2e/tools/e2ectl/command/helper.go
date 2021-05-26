/*
Copyright 2021 The Lynx Authors.

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

package command

import (
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	securityv1alpha1 "github.com/smartxworks/lynx/pkg/apis/security/v1alpha1"
)

func selectEndpoint(ls *metav1.LabelSelector, epList *securityv1alpha1.EndpointList) *securityv1alpha1.EndpointList {
	var selector, _ = metav1.LabelSelectorAsSelector(ls)
	var selected = &securityv1alpha1.EndpointList{}

	for _, ep := range epList.Items {
		if selector.Matches(labels.Set(ep.GetLabels())) {
			selected.Items = append(selected.Items, *ep.DeepCopy())
		}
	}

	return selected
}

func mapJoin(m map[string]string, connector string, separator string) string {
	var str string

	for key, value := range m {
		if str != "" {
			str = str + separator
		}
		str += fmt.Sprintf("%s%s%s", key, connector, value)
	}

	return str
}

func selectorFromString(sl string) *metav1.LabelSelector {
	if sl == "all" {
		// nil for select all endpoint
		return nil
	}

	var list = strings.Split(sl, ",")
	var matchLabels = make(map[string]string, len(list))

	for _, label := range list {
		if len(label) != 0 {
			matchLabels[strings.Split(label, "=")[0]] = strings.Split(label, "=")[1]
		}
	}

	return &metav1.LabelSelector{
		MatchLabels: matchLabels,
	}
}

func labelsFromString(labels string) map[string]string {
	var list = strings.Split(labels, ",")
	var labelMap = make(map[string]string, len(list))

	for _, label := range list {
		if len(label) != 0 {
			labelMap[strings.Split(label, "=")[0]] = strings.Split(label, "=")[1]
		}
	}

	return labelMap
}
