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
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8slabels "k8s.io/apimachinery/pkg/labels"
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
	"github.com/everoute/everoute/pkg/labels"
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
func (r *GroupReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
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

	err = c.Watch(source.Kind(mgr.GetCache(), &securityv1alpha1.Endpoint{}), &handler.Funcs{
		CreateFunc: r.addEndpoint,
		UpdateFunc: r.updateEndpoint,
		DeleteFunc: r.deleteEndpoint,
	})
	if err != nil {
		return err
	}

	err = c.Watch(source.Kind(mgr.GetCache(), &groupv1alpha1.EndpointGroup{}), &handler.Funcs{
		CreateFunc: r.addEndpointGroup,
		UpdateFunc: r.updateEndpointGroup,
		DeleteFunc: r.deleteEndpointGroup,
	})
	if err != nil {
		return err
	}

	return c.Watch(source.Kind(mgr.GetCache(), &corev1.Namespace{}), &handler.Funcs{
		CreateFunc: r.addNamespace,
		UpdateFunc: r.updateNamespace,
		DeleteFunc: r.deleteNamespace,
	})
}

func (r *GroupReconciler) addEndpoint(ctx context.Context, e event.CreateEvent, q workqueue.RateLimitingInterface) {
	endpoint, ok := e.Object.(*securityv1alpha1.Endpoint)
	if !ok {
		klog.Errorf("AddEndpoint received with unavailable object event: %v", e)
	}

	// Ignore endpoint with empty Ips.
	if len(endpoint.Status.IPs) == 0 {
		return
	}

	// Find all endpointgroup keys which match the endpoint's labels.
	groupNameSet := r.filterEndpointGroupsByEndpoint(ctx, endpoint)

	// Enqueue groups to queue for reconciler process.
	for groupName := range groupNameSet {
		q.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
			Namespace: metav1.NamespaceNone,
			Name:      groupName,
		}})
	}
}

func (r *GroupReconciler) updateEndpoint(_ context.Context, e event.UpdateEvent, q workqueue.RateLimitingInterface) {
	newEndpoint, newOK := e.ObjectNew.(*securityv1alpha1.Endpoint)
	oldEndpoint, oldOK := e.ObjectOld.(*securityv1alpha1.Endpoint)
	if !(newOK && oldOK) {
		klog.Errorf("DeleteEndpoint received with unavailable object event: %v", e)
		return
	}

	if k8slabels.Equals(newEndpoint.Labels, oldEndpoint.Labels) &&
		labels.Equals(newEndpoint.Spec.ExtendLabels, oldEndpoint.Spec.ExtendLabels) &&
		utils.EqualIPs(newEndpoint.Status.IPs, oldEndpoint.Status.IPs) &&
		utils.EqualStringSlice(newEndpoint.Status.Agents, oldEndpoint.Status.Agents) {
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

func (r *GroupReconciler) deleteEndpoint(ctx context.Context, e event.DeleteEvent, q workqueue.RateLimitingInterface) {
	endpoint, ok := e.Object.(*securityv1alpha1.Endpoint)
	if !ok {
		klog.Errorf("DeleteEndpoint received with unavailable object event: %v", e)
	}

	// Find all endpointgroup keys which match the endpoint's labels.
	groupNameSet := r.filterEndpointGroupsByEndpoint(ctx, endpoint)

	// Enqueue groups to queue for reconciler process.
	for groupName := range groupNameSet {
		q.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
			Namespace: metav1.NamespaceNone,
			Name:      groupName,
		}})
	}
}

func (r *GroupReconciler) addEndpointGroup(_ context.Context, e event.CreateEvent, q workqueue.RateLimitingInterface) {
	if e.Object == nil {
		klog.Errorf("AddEndpointGroup received with no metadata event: %v", e)
		return
	}

	q.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
		Namespace: e.Object.GetNamespace(),
		Name:      e.Object.GetName(),
	}})
}

// updateEndpointGroup enqueue endpointgroup if endpointgroup need
// to delete or selector update.
func (r *GroupReconciler) updateEndpointGroup(_ context.Context, e event.UpdateEvent, q workqueue.RateLimitingInterface) {
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

	// need to create empty groupmembers
	if len(newGroup.Finalizers) > 0 && len(oldGroup.Finalizers) == 0 {
		q.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
			Namespace: newGroup.Namespace,
			Name:      newGroup.Name,
		}})
	}
}

func (r *GroupReconciler) deleteEndpointGroup(_ context.Context, e event.DeleteEvent, q workqueue.RateLimitingInterface) {
	if e.Object == nil {
		klog.Errorf("DeleteEndpointGroup received with no metadata event: %v", e)
		return
	}

	q.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
		Namespace: e.Object.GetNamespace(),
		Name:      e.Object.GetName(),
	}})
}

func (r *GroupReconciler) addNamespace(_ context.Context, e event.CreateEvent, q workqueue.RateLimitingInterface) {
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

func (r *GroupReconciler) updateNamespace(_ context.Context, e event.UpdateEvent, q workqueue.RateLimitingInterface) {
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

func (r *GroupReconciler) deleteNamespace(_ context.Context, e event.DeleteEvent, q workqueue.RateLimitingInterface) {
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
		endpointNamespaceLabels k8slabels.Set
	)
	namedPortExists := false
	if len(endpoint.Spec.Ports) > 0 {
		namedPortExists = true
	}

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
		// Only SecurityPolicy's named port feature need all-endpoins group,
		// so if endpoint doesn't define named port, it doesn't need to related to the group.
		if group.Name == constants.AllEpWithNamedPort {
			if namedPortExists {
				groupNameSet.Insert(group.Name)
			}
			continue
		}

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

		labelSet, err := labels.AsSet(endpoint.Labels, endpoint.Spec.ExtendLabels)
		if err != nil {
			// this should never happen, the labels has been validated by webhook
			klog.Errorf("invalid enpoint selector %+v: %s", group.Spec.EndpointSelector, err)
			continue
		}

		if !group.Spec.EndpointSelector.Matches(labelSet) {
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
		namespaceLabels = k8slabels.Set(namespace.Labels)
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
	return ctrl.Result{RequeueAfter: time.Nanosecond}, nil
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
	currGroupMembers, err := r.fetchCurrGroupMembers(ctx, &group)
	if err != nil {
		klog.Errorf("while process endpointgroup %s update, can't fetch curr groupmembers: %s", group.Name, err)
		return ctrl.Result{}, err
	}

	members := groupv1alpha1.GroupMembers{}
	members.Name = group.Name
	members.GroupMembers = currGroupMembers.GroupMembers

	err = r.syncGroupMembers(ctx, group.Name, members)
	if err != nil {
		klog.Errorf("failed to sync groupmembers of for group %s: %s", group.Name, err)
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
	isAllEpsGroup := group.Name == constants.AllEpWithNamedPort

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
		endpointList := securityv1alpha1.EndpointList{}
		err := r.List(ctx, &endpointList, client.InNamespace(namespace))
		if err != nil {
			return nil, err
		}

		// list API unsupport custom selector, so we need to filter endpoints here
		for _, endpoint := range endpointList.Items {
			labelSet, err := labels.AsSet(endpoint.Labels, endpoint.Spec.ExtendLabels)
			if err != nil {
				// this should never happen, the labels has been validated by webhook
				return nil, fmt.Errorf("invalid enpoint selector %+v: %s", group.Spec.EndpointSelector, err)
			}
			if group.Spec.EndpointSelector.Matches(labelSet) {
				matchedEndpoints = append(matchedEndpoints, endpoint)
			}
		}
	}

	// conversion endpoint list to member list
	memberList := make([]groupv1alpha1.GroupMember, 0, len(matchedEndpoints))
	for _, ep := range matchedEndpoints {
		if len(ep.Status.IPs) == 0 {
			// skip ep with empty ip addresses
			continue
		}

		if isAllEpsGroup && len(ep.Spec.Ports) == 0 {
			// for AllEndpointsGroup skip endpoint has no named port
			continue
		}

		member := groupv1alpha1.GroupMember{
			EndpointReference: groupv1alpha1.EndpointReference{
				ExternalIDName:  ep.Spec.Reference.ExternalIDName,
				ExternalIDValue: ep.Spec.Reference.ExternalIDValue,
			},
			EndpointAgent: ep.Status.Agents,
			IPs:           ep.Status.IPs,
			Ports:         ep.Spec.Ports,
		}
		memberList = append(memberList, member)
	}

	return &groupv1alpha1.GroupMembers{GroupMembers: memberList}, nil
}

func (r *GroupReconciler) syncGroupMembers(ctx context.Context, groupName string, members groupv1alpha1.GroupMembers) error {
	groupMembers := groupv1alpha1.GroupMembers{}
	err := r.Get(ctx, k8stypes.NamespacedName{Name: groupName}, &groupMembers)
	if err != nil && apierrors.IsNotFound(err) {
		// If not found, create a new groupmembers.
		groupMembers.ObjectMeta = metav1.ObjectMeta{
			Name:      groupName,
			Namespace: metav1.NamespaceNone,
			Labels:    map[string]string{constants.OwnerGroupLabelKey: groupName},
		}
		groupMembers.GroupMembers = members.GroupMembers
		if err = r.Create(ctx, &groupMembers); err != nil {
			return fmt.Errorf("create groupmembers %s: %s", groupName, err)
		}
		klog.Infof("success create groupmembers %s", groupName)
		return nil
	}
	if err != nil {
		return fmt.Errorf("fetch groupmembers %s failed: %s", groupName, err)
	}

	if !r.groupMembersIsDiff(groupMembers.GroupMembers, members.GroupMembers) {
		return nil
	}
	groupMembers.GroupMembers = members.GroupMembers
	if err := r.Update(ctx, &groupMembers); err != nil {
		return fmt.Errorf("update groupmembers %s failed: %s", groupName, err)
	}
	klog.Infof("updated groupmembers %s, members %v", groupMembers.Name, groupMembers.GroupMembers)

	return nil
}

func (r *GroupReconciler) groupMembersIsDiff(a, b []groupv1alpha1.GroupMember) bool {
	if len(a) != len(b) {
		return true
	}
	aMap := make(map[groupv1alpha1.EndpointReference]groupv1alpha1.GroupMember)
	bMap := make(map[groupv1alpha1.EndpointReference]groupv1alpha1.GroupMember)
	for i := range a {
		aMap[a[i].EndpointReference] = a[i]
	}
	for i := range b {
		bMap[b[i].EndpointReference] = b[i]
	}

	if len(aMap) != len(bMap) {
		return true
	}
	for k, v := range aMap {
		bv := bMap[k]
		if !v.Equal(&bv) {
			return true
		}
	}
	return false
}
