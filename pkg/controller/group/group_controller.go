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
	"reflect"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"

	groupv1alpha1 "github.com/everoute/everoute/pkg/apis/group/v1alpha1"
	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	ctrltypes "github.com/everoute/everoute/pkg/controller/types"
	"github.com/everoute/everoute/pkg/utils"
)

// GroupReconciler watch endpoints and endpointgroups resources, create, update
// or delete groupmembers and groupmemberspatches according to group members changes.
type GroupReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// Reconcile receive endpointgroup from work queue, first it create groupmemberspatch,
// then it update groupmembers, latest it clean old groupmemberspatches.
func (r *GroupReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	klog.V(2).Infof("PatchReconciler received group %s members changes", req.NamespacedName)

	group := groupv1alpha1.EndpointGroup{}
	if err := r.Get(ctx, req.NamespacedName, &group); err != nil {
		klog.Errorf("unable to fetch endpointGroup %s: %s", req.Name, err.Error())
		// we'll ignore not-found errors, since they can't be fixed by an immediate
		// requeue (we'll need to wait for a new notification), and we can get them
		// on deleted requests.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if r.isNewEndpointGroup(&group) {
		klog.Infof("process endpointgroup %s create request", group.Name)
		return r.processEndpointGroupCreate(ctx, &group)
	}

	if r.isDeletingEndpointGroup(&group) {
		klog.Infof("process endpointgroup %s delete request", group.Name)
		return r.processEndpointGroupDelete(ctx, &group)
	}

	return r.processEndpointGroupUpdate(ctx, group)
}

// SetupWithManager create and add Group Controller to the manager.
func (r *GroupReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if mgr == nil {
		return fmt.Errorf("can't setup with nil manager")
	}

	c, err := controller.New("group-controller", mgr, controller.Options{
		MaxConcurrentReconciles: constants.DefaultMaxConcurrentReconciles,
		Reconciler:              r,
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &securityv1alpha1.Endpoint{}}, &handler.Funcs{
		CreateFunc: r.addEndpoint,
		UpdateFunc: r.updateEndpoint,
		DeleteFunc: r.deleteEndpoint,
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &groupv1alpha1.EndpointGroup{}}, &handler.Funcs{
		CreateFunc: r.addEndpointGroup,
		UpdateFunc: r.updateEndpointGroup,
		DeleteFunc: r.deleteEndpointGroup,
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &corev1.Namespace{}}, &handler.Funcs{
		CreateFunc: r.addNamespace,
		UpdateFunc: r.updateNamespace,
		DeleteFunc: r.deleteNamespace,
	})
	if err != nil {
		return err
	}

	return nil
}

func (r *GroupReconciler) addEndpoint(e event.CreateEvent, q workqueue.RateLimitingInterface) {
	endpoint, ok := e.Object.(*securityv1alpha1.Endpoint)
	if !ok {
		klog.Errorf("AddEndpoint received with unavailable object event: %v", e)
	}

	// Ignore endpoint with empty Ips.
	if len(endpoint.Status.IPs) == 0 {
		return
	}

	// Find all endpointgroup keys which match the endpoint's labels.
	groupNameSet := r.filterEndpointGroupsByEndpoint(context.Background(), endpoint)

	// Enqueue groups to queue for reconciler process.
	for groupName := range groupNameSet {
		q.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
			Namespace: metav1.NamespaceNone,
			Name:      groupName,
		}})
	}
}

func (r *GroupReconciler) updateEndpoint(e event.UpdateEvent, q workqueue.RateLimitingInterface) {
	newEndpoint, newOK := e.ObjectNew.(*securityv1alpha1.Endpoint)
	oldEndpoint, oldOK := e.ObjectOld.(*securityv1alpha1.Endpoint)
	if !(newOK && oldOK) {
		klog.Errorf("DeleteEndpoint received with unavailable object event: %v", e)
		return
	}

	if labels.Equals(newEndpoint.Labels, oldEndpoint.Labels) &&
		utils.EqualIPs(newEndpoint.Status.IPs, oldEndpoint.Status.IPs) {
		return
	}

	ctx := context.Background()
	oldGroupSet := r.filterEndpointGroupsByEndpoint(ctx, oldEndpoint)
	newGroupSet := r.filterEndpointGroupsByEndpoint(ctx, newEndpoint)

	for groupName := range oldGroupSet.Union(newGroupSet) {
		q.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
			Namespace: metav1.NamespaceNone,
			Name:      groupName,
		}})
	}
}

func (r *GroupReconciler) deleteEndpoint(e event.DeleteEvent, q workqueue.RateLimitingInterface) {
	endpoint, ok := e.Object.(*securityv1alpha1.Endpoint)
	if !ok {
		klog.Errorf("DeleteEndpoint received with unavailable object event: %v", e)
	}

	// Find all endpointgroup keys which match the endpoint's labels.
	groupNameSet := r.filterEndpointGroupsByEndpoint(context.Background(), endpoint)

	// Enqueue groups to queue for reconciler process.
	for groupName := range groupNameSet {
		q.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
			Namespace: metav1.NamespaceNone,
			Name:      groupName,
		}})
	}
}

func (r *GroupReconciler) addEndpointGroup(e event.CreateEvent, q workqueue.RateLimitingInterface) {
	if e.Meta == nil {
		klog.Errorf("AddEndpointGroup received with no metadata event: %v", e)
		return
	}

	q.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
		Namespace: e.Meta.GetNamespace(),
		Name:      e.Meta.GetName(),
	}})
}

// updateEndpointGroup enqueue endpointgroup if endpointgroup need
// to delete or selector update.
func (r *GroupReconciler) updateEndpointGroup(e event.UpdateEvent, q workqueue.RateLimitingInterface) {
	newGroup, newOK := e.ObjectNew.(*groupv1alpha1.EndpointGroup)
	oldGroup, oldOK := e.ObjectOld.(*groupv1alpha1.EndpointGroup)

	if !(newOK && oldOK) {
		klog.Errorf("UpdateEndpointGroup received with unavailable object event: %v", e)
		return
	}

	if r.isDeletingEndpointGroup(newGroup) {
		q.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
			Namespace: newGroup.Namespace,
			Name:      newGroup.Name,
		}})
		return
	}

	if !reflect.DeepEqual(newGroup.Spec, oldGroup.Spec) {
		q.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
			Namespace: newGroup.Namespace,
			Name:      newGroup.Name,
		}})
	}
}

func (r *GroupReconciler) deleteEndpointGroup(e event.DeleteEvent, q workqueue.RateLimitingInterface) {
	if e.Meta == nil {
		klog.Errorf("DeleteEndpointGroup received with no metadata event: %v", e)
		return
	}

	q.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
		Namespace: e.Meta.GetNamespace(),
		Name:      e.Meta.GetName(),
	}})
}

func (r *GroupReconciler) addNamespace(e event.CreateEvent, q workqueue.RateLimitingInterface) {
	newNamespace := e.Object.(*corev1.Namespace)
	groupNameSet := r.filterEndpointGroupsByNamespace(context.Background(), newNamespace)

	// Enqueue groups to queue for reconciler process.
	for groupName := range groupNameSet {
		q.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
			Namespace: metav1.NamespaceNone,
			Name:      groupName,
		}})
	}
}

func (r *GroupReconciler) updateNamespace(e event.UpdateEvent, q workqueue.RateLimitingInterface) {
	oldNamespace := e.ObjectOld.(*corev1.Namespace)
	newNamespace := e.ObjectNew.(*corev1.Namespace)

	// ignore namespace no labels changes
	if reflect.DeepEqual(newNamespace.Labels, oldNamespace.Labels) {
		return
	}

	ctx := context.Background()
	oldGroupSet := r.filterEndpointGroupsByNamespace(ctx, oldNamespace)
	newGroupSet := r.filterEndpointGroupsByNamespace(ctx, newNamespace)

	for groupName := range newGroupSet.Union(oldGroupSet) {
		q.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
			Namespace: metav1.NamespaceNone,
			Name:      groupName,
		}})
	}
}

func (r *GroupReconciler) deleteNamespace(e event.DeleteEvent, q workqueue.RateLimitingInterface) {
	oldNamespace := e.Object.(*corev1.Namespace)
	groupNameSet := r.filterEndpointGroupsByNamespace(context.Background(), oldNamespace)

	// Enqueue groups to queue for reconciler process.
	for groupName := range groupNameSet {
		q.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
			Namespace: metav1.NamespaceNone,
			Name:      groupName,
		}})
	}
}

// filterEndpointGroupsByEndpoint filter endpointgroups which match endpoint labels.
func (r *GroupReconciler) filterEndpointGroupsByEndpoint(ctx context.Context, endpoint *securityv1alpha1.Endpoint) sets.String {
	var (
		groupNameSet            = sets.String{}
		groupList               groupv1alpha1.EndpointGroupList
		endpointNamespaceLabels labels.Set
	)

	err := r.List(ctx, &groupList)
	if err != nil {
		klog.Errorf("list endpoint group: %s", err)
		return nil
	}

	// fetch endpoint namespace labels
	endpointNamespace := &corev1.Namespace{}
	err = r.Get(ctx, client.ObjectKey{Name: endpoint.Namespace}, endpointNamespace)
	if err != nil {
		klog.Errorf("get namespace %+v: %s", endpoint.Namespace, err)
		return nil
	}
	endpointNamespaceLabels = endpointNamespace.Labels

	for _, group := range groupList.Items {
		// if endpoint set, match endpoint name and namespace
		if group.Spec.Endpoint != nil {
			if group.Spec.Endpoint.Name == endpoint.Name && group.Spec.Endpoint.Namespace == endpoint.Namespace {
				groupNameSet.Insert(group.Name)
				continue
			}
		}

		// if namespace set, matched endpoint must in the namespace
		if group.Spec.Namespace != nil && endpoint.GetNamespace() != *group.Spec.Namespace {
			continue
		}

		// if namespaceSelector set, matched endpoint must in the selected namespaces
		if group.Spec.NamespaceSelector != nil {
			namespaceSelector, err := metav1.LabelSelectorAsSelector(group.Spec.NamespaceSelector)
			if err != nil {
				klog.Errorf("invalid namespace selector %+v: %s", group.Spec.NamespaceSelector, err)
				continue
			}
			// continue if namespace not match
			if !namespaceSelector.Matches(endpointNamespaceLabels) {
				continue
			}
		}

		endpointSelector, err := metav1.LabelSelectorAsSelector(group.Spec.EndpointSelector)
		if err != nil {
			klog.Errorf("invalid enpoint selector %+v: %s", group.Spec.EndpointSelector, err)
			continue
		}

		if !endpointSelector.Matches(labels.Set(endpoint.Labels)) {
			continue
		}

		groupNameSet.Insert(group.Name)
	}

	return groupNameSet
}

// filterEndpointGroupsByNamespace filter endpointgroups which match Namespace labels.
func (r *GroupReconciler) filterEndpointGroupsByNamespace(ctx context.Context, namespace *corev1.Namespace) sets.String {
	var (
		groupNameSet    = sets.String{}
		namespaceLabels = labels.Set(namespace.Labels)
		groupList       groupv1alpha1.EndpointGroupList
	)

	err := r.List(ctx, &groupList)
	if err != nil {
		klog.Errorf("list endpoint group: %s", err)
		return nil
	}

	for _, group := range groupList.Items {
		// if group has select this namespace, pick it out
		if group.Spec.Namespace != nil && namespace.Name == *group.Spec.Namespace {
			groupNameSet.Insert(group.GetName())
			continue
		}

		// if namespaceSelector set, matched endpoint must in the selected namespaces
		if group.Spec.NamespaceSelector != nil {
			namespaceSelector, err := metav1.LabelSelectorAsSelector(group.Spec.NamespaceSelector)
			if err != nil {
				klog.Errorf("invalid namespace selector %+v: %s", group.Spec.NamespaceSelector, err)
				continue
			}

			// if namespace selector match the namespace, pick it out
			if namespaceSelector.Matches(namespaceLabels) {
				groupNameSet.Insert(group.GetName())
				continue
			}
		}
	}

	return groupNameSet
}

func (r *GroupReconciler) isNewEndpointGroup(group *groupv1alpha1.EndpointGroup) bool {
	return group.ObjectMeta.DeletionTimestamp == nil &&
		len(group.ObjectMeta.Finalizers) == 0
}

func (r *GroupReconciler) isDeletingEndpointGroup(group *groupv1alpha1.EndpointGroup) bool {
	return group.ObjectMeta.DeletionTimestamp != nil
}

func (r *GroupReconciler) processEndpointGroupCreate(ctx context.Context, group *groupv1alpha1.EndpointGroup) (ctrl.Result, error) {
	klog.V(2).Infof("add finalizers for new endpointgroup %s", group.Name)

	group.ObjectMeta.Finalizers = []string{constants.DependentsCleanFinalizer}

	err := r.Update(ctx, group)
	if err != nil {
		klog.Errorf("failed to update endpointgroup %s: %s", group.Name, err.Error())
		return ctrl.Result{}, err
	}

	// Requeue for create groupmembers and patches for this group.
	return ctrl.Result{Requeue: true}, nil
}

func (r *GroupReconciler) processEndpointGroupDelete(ctx context.Context, group *groupv1alpha1.EndpointGroup) (ctrl.Result, error) {
	klog.V(2).Infof("clean group dependents for deleting endpointgroup %s", group.Name)

	// clean all group dependents groupmembers & groupmemberslist
	err := r.DeleteAllOf(ctx, &groupv1alpha1.GroupMembersPatch{}, client.MatchingLabels{constants.OwnerGroupLabelKey: group.Name})
	if err != nil {
		klog.Errorf("failed to delete endpointgroup %s dependents: %s", group.Name, err.Error())
		return ctrl.Result{}, err
	}

	err = r.DeleteAllOf(ctx, &groupv1alpha1.GroupMembers{}, client.MatchingLabels{constants.OwnerGroupLabelKey: group.Name})
	if err != nil {
		klog.Errorf("failed to delete endpointgroup %s dependents: %s", group.Name, err.Error())
		return ctrl.Result{}, err
	}

	group.ObjectMeta.Finalizers = []string{}
	err = r.Update(ctx, group)
	if err != nil {
		klog.Errorf("failed to update endpointgroup %s: %s", group.Name, err.Error())
	}

	return ctrl.Result{}, err
}

// processEndpointGroupUpdate sync endpointgroup members by CRUD groupmembers and groupmemberspath object.
func (r *GroupReconciler) processEndpointGroupUpdate(ctx context.Context, group groupv1alpha1.EndpointGroup) (ctrl.Result, error) {
	prevGroupMembers, err := r.fetchPrevGroupMembers(ctx, &group)
	if err != nil {
		klog.Errorf("while process endpointgroup %s update, can't fetch prev groupmembers: %s", group.Name, err)
		return ctrl.Result{}, err
	}

	currGroupMembers, err := r.fetchCurrGroupMembers(ctx, &group)
	if err != nil {
		klog.Errorf("while process endpointgroup %s update, can't fetch curr groupmembers: %s", group.Name, err)
		return ctrl.Result{}, err
	}

	members := groupv1alpha1.GroupMembers{}
	members.Name = group.Name
	members.GroupMembers = currGroupMembers.GroupMembers

	patch := ToGroupMembersPatch(prevGroupMembers, currGroupMembers)
	if IsEmptyPatch(patch) {
		members.Revision = prevGroupMembers.Revision
	} else {
		patch.AppliedToGroupMembers = groupv1alpha1.GroupMembersReference{
			Name:     group.Name,
			Revision: prevGroupMembers.Revision,
		}
		members.Revision = prevGroupMembers.Revision + 1
	}

	err = r.syncGroupMembersPatch(ctx, group.Name, patch)
	if err != nil {
		klog.Errorf("failed to sync patch of revision %d for group %s: %s", members.Revision, group.Name, err)
		return ctrl.Result{}, err
	}

	err = r.syncGroupMembers(ctx, group.Name, members)
	if err != nil {
		klog.Errorf("failed to sync groupmembers of revision %d for group %s: %s", members.Revision, group.Name, err)
		return ctrl.Result{}, err
	}

	err = r.cleanupOldPatches(ctx, group.Name, members.Revision)
	if err != nil {
		klog.Errorf("wile remove old patches of group %s: %s", group.Name, err)
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// fetchCurrGroupMembers get endpoints by selector, and return as GroupMembers
func (r *GroupReconciler) fetchCurrGroupMembers(ctx context.Context, group *groupv1alpha1.EndpointGroup) (*groupv1alpha1.GroupMembers, error) {
	var (
		matchedNamespaces []string
		matchedEndpoints  []securityv1alpha1.Endpoint
	)

	// filter matched namespace
	if group.Spec.Namespace == nil && group.Spec.NamespaceSelector == nil {
		// If neither of NamespaceSelector or Namespace set, then the EndpointGroup
		// would select the endpoints in all namespaces.
		matchedNamespaces = []string{metav1.NamespaceAll}
	} else {
		if group.Spec.Namespace != nil {
			// If Namespace is set, then the EndpointGroup would select the endpoints
			// matching EndpointSelector in the specific Namespace.
			matchedNamespaces = append(matchedNamespaces, *group.Spec.Namespace)
		} else {
			// If NamespaceSelector is set, then the EndpointGroup would select the endpoints
			// matching EndpointSelector in the Namespaces selected by NamespaceSelector.
			namespaceSelector, err := metav1.LabelSelectorAsSelector(group.Spec.NamespaceSelector)
			if err != nil {
				return nil, fmt.Errorf("invalid namespace selector %+v: %s", group.Spec.NamespaceSelector, err)
			}

			namespaceList := corev1.NamespaceList{}
			err = r.List(ctx, &namespaceList, client.MatchingLabelsSelector{Selector: namespaceSelector})
			if err != nil {
				return nil, fmt.Errorf("list namespaces: %s", err)
			}

			for _, namespace := range namespaceList.Items {
				matchedNamespaces = append(matchedNamespaces, namespace.GetName())
			}
		}
	}

	if group.Spec.Endpoint != nil {
		var endpoint securityv1alpha1.Endpoint
		err := r.Get(ctx, k8stypes.NamespacedName{Name: group.Spec.Endpoint.Name, Namespace: group.Spec.Endpoint.Namespace}, &endpoint)
		// ignore non-existent endpoint
		if err != nil && !apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("failed to get endpoint: %s, err: %s", group.Spec.Endpoint, err)
		}
		if err == nil {
			matchedEndpoints = append(matchedEndpoints, endpoint)
		}
	}

	for _, namespace := range matchedNamespaces {
		// filter endpoints in specify namespace
		endpointSelector, err := metav1.LabelSelectorAsSelector(group.Spec.EndpointSelector)
		if err != nil {
			return nil, err
		}

		endpointList := securityv1alpha1.EndpointList{}
		err = r.List(ctx, &endpointList, client.MatchingLabelsSelector{Selector: endpointSelector}, client.InNamespace(namespace))
		if err != nil {
			return nil, err
		}
		matchedEndpoints = append(matchedEndpoints, endpointList.Items...)
	}

	// conversion endpoint list to member list
	memberList := make([]groupv1alpha1.GroupMember, 0, len(matchedEndpoints))
	for _, ep := range matchedEndpoints {
		if len(ep.Status.IPs) == 0 {
			// skip ep with empty ip addresses
			continue
		}

		member := groupv1alpha1.GroupMember{
			EndpointReference: groupv1alpha1.EndpointReference{
				ExternalIDName:  ep.Spec.Reference.ExternalIDName,
				ExternalIDValue: ep.Spec.Reference.ExternalIDValue,
			},
			IPs: ep.Status.IPs,
		}
		memberList = append(memberList, member)
	}

	return &groupv1alpha1.GroupMembers{GroupMembers: memberList}, nil
}

// fetchPrevGroupMembers read groupmembers and groupmemberspatches, calculate
// latest revision of groupmembers.
func (r *GroupReconciler) fetchPrevGroupMembers(ctx context.Context, group *groupv1alpha1.EndpointGroup) (*groupv1alpha1.GroupMembers, error) {
	groupMembers := groupv1alpha1.GroupMembers{}
	err := r.Get(ctx, k8stypes.NamespacedName{Name: group.Name}, &groupMembers)
	// Ignore not found error, because groupMembers may haven't create yet.
	if client.IgnoreNotFound(err) != nil {
		return nil, err
	}

	patchList := groupv1alpha1.GroupMembersPatchList{}
	err = r.List(ctx, &patchList, client.MatchingLabels{constants.OwnerGroupLabelKey: group.Name})
	if err != nil {
		return nil, err
	}

	ApplyGroupMembersPatches(&groupMembers, patchList.Items)

	return &groupMembers, nil
}

func (r *GroupReconciler) syncGroupMembers(ctx context.Context, groupName string, members groupv1alpha1.GroupMembers) error {
	groupMembers := groupv1alpha1.GroupMembers{}
	err := r.Get(ctx, k8stypes.NamespacedName{Name: groupName}, &groupMembers)
	if err != nil && apierrors.IsNotFound(err) {
		// If not found, create a new empty groupmembers with revision 0.
		groupMembers.ObjectMeta = metav1.ObjectMeta{
			Name:      groupName,
			Namespace: metav1.NamespaceNone,
			Labels:    map[string]string{constants.OwnerGroupLabelKey: groupName},
		}
		if err = r.Create(ctx, &groupMembers); err != nil {
			return fmt.Errorf("create groupmembers %s: %s", groupName, err)
		}
	}
	if err != nil {
		return fmt.Errorf("fetch groupmembers %s: %s", groupName, err)
	}

	if groupMembers.Revision >= members.Revision {
		// GroupMembers has already a high revision, ignore
		return nil
	}

	groupMembers.GroupMembers = members.GroupMembers
	groupMembers.Revision = members.Revision
	if err := r.Update(ctx, &groupMembers); err != nil {
		return fmt.Errorf("fetch groupmembers %s: %s", groupName, err)
	}
	klog.Infof("updated groupmembers %s to revision %d, numbers of members %d", groupMembers.Name, groupMembers.Revision, len(groupMembers.GroupMembers))

	return nil
}

func (r *GroupReconciler) syncGroupMembersPatch(ctx context.Context, groupName string, patch groupv1alpha1.GroupMembersPatch) error {
	if IsEmptyPatch(patch) {
		return nil
	}

	patch.ObjectMeta = metav1.ObjectMeta{
		Name:      fmt.Sprintf("patch-%s-revision%d", groupName, patch.AppliedToGroupMembers.Revision),
		Namespace: metav1.NamespaceNone,
		Labels:    map[string]string{constants.OwnerGroupLabelKey: groupName},
	}
	if err := r.Create(ctx, &patch); err != nil {
		return fmt.Errorf("create patch %s: %s", patch.Name, err)
	}
	klog.Infof("create groupmemberspatch %s, %+v", patch.Name, showGroupMembersPatch(patch))

	return nil
}

// cleanupOldPatches remove pathes which revision under <revision> for group <groupName>, but we will always
// retained the nearest three groupMembersPatches for debug.
func (r *GroupReconciler) cleanupOldPatches(ctx context.Context, groupName string, revision int32) error {
	patchList := groupv1alpha1.GroupMembersPatchList{}
	if err := r.List(ctx, &patchList, client.MatchingLabels{constants.OwnerGroupLabelKey: groupName}); err != nil {
		return err
	}

	for _, patch := range patchList.Items {
		if patch.AppliedToGroupMembers.Revision >= revision {
			continue
		}
		// Retained the nearest three groupMembersPatches for debug.
		if (revision - patch.AppliedToGroupMembers.Revision) <= constants.NumOfRetainedGroupMembersPatches {
			continue
		}

		if err := r.Delete(ctx, &patch); err != nil {
			klog.Errorf("unabled to delete old groupmemberspatch %s: %s", patch.Name, err.Error())
			return err
		}
		klog.Infof("deleted old groupmemberspatch %s", patch.Name)
	}

	return nil
}

// ToGroupMembersPatch calculate the patch between two groupmembers.
func ToGroupMembersPatch(prev *groupv1alpha1.GroupMembers, curr *groupv1alpha1.GroupMembers) groupv1alpha1.GroupMembersPatch {
	prevEpMap := make(map[groupv1alpha1.EndpointReference]groupv1alpha1.GroupMember)
	patch := groupv1alpha1.GroupMembersPatch{}

	if prev == nil {
		prev = new(groupv1alpha1.GroupMembers)
	}
	if curr == nil {
		curr = new(groupv1alpha1.GroupMembers)
	}

	for _, member := range prev.GroupMembers {
		prevEpMap[member.EndpointReference] = member
	}

	for _, member := range curr.GroupMembers {
		prevEp, ok := prevEpMap[member.EndpointReference]
		if !ok {
			// If member not found in prevGroupMebers, it's a new member.
			patch.AddedGroupMembers = append(patch.AddedGroupMembers, member)
		} else {
			if !utils.EqualIPs(prevEp.IPs, member.IPs) {
				// If member IPs changes, it's an update member.
				patch.UpdatedGroupMembers = append(patch.UpdatedGroupMembers, member)
			}
		}
		// Remove processed endpoint.
		delete(prevEpMap, member.EndpointReference)
	}

	for _, member := range prevEpMap {
		patch.RemovedGroupMembers = append(patch.RemovedGroupMembers, member)
	}

	return patch
}

// IsEmptyPatch return true if and only if the patch is empty.
func IsEmptyPatch(patch groupv1alpha1.GroupMembersPatch) bool {
	return len(patch.RemovedGroupMembers) == 0 &&
		len(patch.AddedGroupMembers) == 0 &&
		len(patch.UpdatedGroupMembers) == 0
}

// ApplyGroupMembersPatches apply GroupMemberPatches to GroupMembers.
func ApplyGroupMembersPatches(groupmembers *groupv1alpha1.GroupMembers, patches []groupv1alpha1.GroupMembersPatch) {
	var patchSet = make(map[int32]groupv1alpha1.GroupMembersPatch, len(patches))

	for _, patch := range patches {
		patchSet[patch.AppliedToGroupMembers.Revision] = patch
	}

	for {
		patch, ok := patchSet[groupmembers.Revision]
		if !ok {
			break
		}
		applyGroupMembersPatch(groupmembers, patch)
		groupmembers.Revision++
	}
}

func applyGroupMembersPatch(groupmembers *groupv1alpha1.GroupMembers, patch groupv1alpha1.GroupMembersPatch) {
	var members = make(map[groupv1alpha1.EndpointReference]groupv1alpha1.GroupMember)

	for _, member := range groupmembers.GroupMembers {
		members[member.EndpointReference] = member
	}

	for _, member := range append(patch.AddedGroupMembers, patch.UpdatedGroupMembers...) {
		members[member.EndpointReference] = member
	}

	for _, member := range patch.RemovedGroupMembers {
		delete(members, member.EndpointReference)
	}

	var memberList []groupv1alpha1.GroupMember
	for _, member := range members {
		memberList = append(memberList, member)
	}

	groupmembers.GroupMembers = memberList
}

// showGroupMembersPatch show members change info as string.
// format like:
//   AddMember: {ID:"idk1/idv1", IPs:[192.168.1.1]}, {ID:"idk2/idv2", IPs:[192.168.2.1]} DelMember: {ID:"idk3/idv3"}
func showGroupMembersPatch(patch groupv1alpha1.GroupMembersPatch) string {
	toString := func(head string, members []groupv1alpha1.GroupMember) (str string) {
		for _, member := range members {
			id := ctrltypes.ExternalID{
				Name:  member.EndpointReference.ExternalIDName,
				Value: member.EndpointReference.ExternalIDValue,
			}
			str = fmt.Sprintf("{ID:%s%s, IPs:%v}, ", str, id.String(), member.IPs)
		}
		if str == "" {
			return ""
		}
		return fmt.Sprintf("%s: %s ", head, str[:len(str)-2])
	}

	return fmt.Sprint(
		toString("AddMember", patch.AddedGroupMembers),
		toString("UpdMember", patch.UpdatedGroupMembers),
		toString("DelMember", patch.RemovedGroupMembers),
	)
}
