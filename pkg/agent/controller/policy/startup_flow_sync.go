/*
Copyright 2026 The Everoute Authors.

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

package policy

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"

	groupv1alpha1 "github.com/everoute/everoute/pkg/apis/group/v1alpha1"
	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/common/startupsync"
)

var startupPolicySyncRequest = k8stypes.NamespacedName{Name: "__everoute_startup_policy_sync__"}
var startupGroupMembersSyncRequest = k8stypes.NamespacedName{Name: "__everoute_startup_groupmembers_sync__"}
var startupGlobalPolicySyncRequest = k8stypes.NamespacedName{Name: "__everoute_startup_global_policy_sync__"}

func (r *Reconciler) EnqueueStartupFlowSync(ctx context.Context) {
	if r.StartupFlowSync == nil {
		return
	}
	r.startupPolicySync.Enqueue(ctx)
	r.startupGroupMembersSync.Enqueue(ctx)
	r.startupGlobalPolicySync.Enqueue(ctx)
}

func (r *Reconciler) initStartupPolicyReconciler() {
	r.startupPolicySync = &startupsync.Reconciler{
		Request:  startupPolicySyncRequest,
		Queue:    r.StartupPolicyQueue,
		Name:     "securityPolicy",
		Resource: "policy",
		NewObject: func(key k8stypes.NamespacedName) client.Object {
			return &securityv1alpha1.SecurityPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name},
			}
		},
		Completion: &startupsync.Completion{
			ListExpected:        r.listStartupPolicyKeys,
			MarkDone:            r.markStartupNormalPolicyDone,
			RequeueOnCheckError: true,
		},
	}
}

func (r *Reconciler) initStartupGroupMembersReconciler() {
	r.startupGroupMembersSync = &startupsync.Reconciler{
		Request:  startupGroupMembersSyncRequest,
		Queue:    r.StartupGroupMembersQueue,
		Name:     "groupMembers",
		Resource: "groupMembers",
		NewObject: func(key k8stypes.NamespacedName) client.Object {
			return &groupv1alpha1.GroupMembers{
				ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name},
			}
		},
		Completion: &startupsync.Completion{
			ListExpected:        r.listStartupGroupMembersKeys,
			MarkDone:            r.markStartupNormalPolicyDone,
			RequeueOnCheckError: true,
		},
	}
}

func (r *Reconciler) initStartupGlobalPolicyReconciler() {
	r.startupGlobalPolicySync = &startupsync.Reconciler{
		Request:  startupGlobalPolicySyncRequest,
		Queue:    r.StartupGlobalPolicyQueue,
		Name:     "globalPolicy",
		Resource: "globalPolicy",
		NewObject: func(key k8stypes.NamespacedName) client.Object {
			return &securityv1alpha1.GlobalPolicy{
				ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name},
			}
		},
	}
}

func (r *Reconciler) listStartupPolicyKeys(ctx context.Context) (sets.Set[string], error) {
	policyList := securityv1alpha1.SecurityPolicyList{}
	if err := r.List(ctx, &policyList); err != nil {
		return nil, err
	}
	expected := sets.New[string]()
	for i := range policyList.Items {
		key := client.ObjectKeyFromObject(&policyList.Items[i])
		expected.Insert(key.String())
	}
	return expected, nil
}

func (r *Reconciler) listStartupGroupMembersKeys(ctx context.Context) (sets.Set[string], error) {
	groupMembersList := groupv1alpha1.GroupMembersList{}
	if err := r.List(ctx, &groupMembersList); err != nil {
		return nil, err
	}
	expected := sets.New[string]()
	for i := range groupMembersList.Items {
		key := client.ObjectKeyFromObject(&groupMembersList.Items[i])
		expected.Insert(key.String())
	}
	return expected, nil
}

func (r *Reconciler) markStartupNormalPolicyDone() {
	if r.startupPolicySync == nil || r.startupPolicySync.Completion == nil ||
		r.startupGroupMembersSync == nil || r.startupGroupMembersSync.Completion == nil {
		return
	}
	if r.startupPolicySync.Completion.IsDone() && r.startupGroupMembersSync.Completion.IsDone() {
		r.StartupFlowSync.MarkNormalPolicyDone()
	}
}
