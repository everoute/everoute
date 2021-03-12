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

package cache

import (
	"sync"

	"k8s.io/klog"

	groupv1alpha1 "github.com/smartxworks/lynx/pkg/apis/group/v1alpha1"
)

type GroupPatch struct {
	// GroupName is group Name which should applied to.
	GroupName string
	// Revision is group Revision which should applied to.
	Revision int32

	// Add is the Add IPBlocks if patch applied.
	Add []string
	// Del is the deleted IPBlocks if patch applied.
	Del []string
}

type groupMembership struct {
	name      string
	revision  int32
	endpoints map[groupv1alpha1.EndpointReference]groupv1alpha1.GroupMember
}

// GroupCache cache GroupMembers and GroupMembersPatch, it's thread safe.
type GroupCache struct {
	lock sync.RWMutex

	// patches storage patches by groupName and revision.
	patches map[string]map[int32]*groupv1alpha1.GroupMembersPatch
	members map[string]*groupMembership
}

// NewGroupCache return a new GroupCache.
func NewGroupCache() *GroupCache {
	return &GroupCache{
		patches: make(map[string]map[int32]*groupv1alpha1.GroupMembersPatch),
		members: make(map[string]*groupMembership),
	}
}

// AddPatch add a GroupMembersPatch to patches.
func (cache *GroupCache) AddPatch(patch *groupv1alpha1.GroupMembersPatch) {
	var groupName = patch.AppliedToGroupMembers.Name
	var revision = patch.AppliedToGroupMembers.Revision

	cache.lock.Lock()
	defer cache.lock.Unlock()

	// todo: verify whether the patch generated for this group (by uuid)
	membership, exist := cache.members[groupName]
	if exist && revision < membership.revision {
		klog.V(2).Infof("ignore old revision %d of patch %s", revision, patch.Name)
		return
	}

	if _, exist := cache.patches[groupName]; !exist {
		// create patch event may get first (before groupmembers create event).
		cache.patches[groupName] = make(map[int32]*groupv1alpha1.GroupMembersPatch)
	}

	cache.patches[groupName][revision] = patch
}

// NextPatch return a patch with the same revision of current GroupMembers.
// Nil patch means not exist next patch.
func (cache *GroupCache) NextPatch(groupName string) *GroupPatch {
	cache.lock.RLock()
	defer cache.lock.RUnlock()

	membership, ok := cache.members[groupName]
	if !ok {
		return nil
	}

	sourcePatch, ok := cache.patches[groupName][membership.revision]
	if !ok {
		return nil
	}

	patch := &GroupPatch{
		GroupName: groupName,
		Revision:  membership.revision,
	}

	for _, member := range sourcePatch.AddedGroupMembers {
		for _, ipAddr := range member.IPs {
			patch.Add = append(patch.Add, GetIPCidr(ipAddr))
		}
	}

	for _, member := range sourcePatch.UpdatedGroupMembers {
		oldMember := membership.endpoints[member.EndpointReference]
		for _, ipAddr := range oldMember.IPs {
			patch.Del = append(patch.Del, GetIPCidr(ipAddr))
		}
		for _, ipAddr := range member.IPs {
			patch.Add = append(patch.Add, GetIPCidr(ipAddr))
		}
	}

	for _, member := range sourcePatch.RemovedGroupMembers {
		for _, ipAddr := range member.IPs {
			patch.Del = append(patch.Del, GetIPCidr(ipAddr))
		}
	}

	return patch
}

// ApplyPatch applied patch to cache GroupMembers. ApplyPatch should be called
// after the GroupPatch successfully processed.
func (cache *GroupCache) ApplyPatch(patch *GroupPatch) {
	var groupName = patch.GroupName
	var revision = patch.Revision

	cache.lock.Lock()
	defer cache.lock.Unlock()

	membership, ok := cache.members[groupName]
	if !ok {
		klog.Warningf("when apply patch of revision %d, group %s not found", patch.Revision, groupName)
		return
	}

	if revision != membership.revision {
		klog.Fatalf("expected state! patch revision %d can't applied to group %s revision %d", revision, groupName, membership.revision)
	}

	sourcePatch, ok := cache.patches[groupName][revision]
	if !ok {
		// patch has been applied
		return
	}

	for _, member := range sourcePatch.AddedGroupMembers {
		membership.endpoints[member.EndpointReference] = member
	}
	for _, member := range sourcePatch.UpdatedGroupMembers {
		membership.endpoints[member.EndpointReference] = member
	}
	for _, member := range sourcePatch.RemovedGroupMembers {
		delete(membership.endpoints, member.EndpointReference)
	}

	// upgrade to a new Revision
	membership.revision = revision + 1

	delete(cache.patches[groupName], revision)
}

// PatchLen return patches length of the giving group.
func (cache *GroupCache) PatchLen(groupName string) int {
	return len(cache.patches[groupName])
}

// AddGroupMembership add GroupMembers to cache.
func (cache *GroupCache) AddGroupMembership(members *groupv1alpha1.GroupMembers) {
	cache.lock.Lock()
	defer cache.lock.Unlock()

	if _, exist := cache.members[members.Name]; exist {
		klog.Warningf("add groupmembers %s already exist in cache", members.Name)
		return
	}

	membership := &groupMembership{
		name:      members.Name,
		revision:  members.Revision,
		endpoints: make(map[groupv1alpha1.EndpointReference]groupv1alpha1.GroupMember),
	}

	for _, member := range members.GroupMembers {
		membership.endpoints[member.EndpointReference] = member
	}

	if _, ok := cache.patches[members.Name]; !ok {
		cache.patches[members.Name] = make(map[int32]*groupv1alpha1.GroupMembersPatch)
	}

	// remove old revision of patches create before GroupMembership
	for revision := range cache.patches[members.Name] {
		if revision < membership.revision {
			delete(cache.patches[members.Name], revision)
		}
	}

	cache.members[members.Name] = membership
}

// DelGroupMembership removed GroupMembers and it's patches from cache.
func (cache *GroupCache) DelGroupMembership(groupName string) {
	cache.lock.Lock()
	defer cache.lock.Unlock()

	delete(cache.patches, groupName)
	delete(cache.members, groupName)
}

// ListGroupIPBlocks return a list of IPBlocks of the group.
func (cache *GroupCache) ListGroupIPBlocks(groupName string) (revision int32, ipBlocks []string, exist bool) {
	cache.lock.RLock()
	defer cache.lock.RUnlock()

	membership, ok := cache.members[groupName]
	if !ok {
		return 0, nil, false
	}

	for _, member := range membership.endpoints {
		for _, ipAddr := range member.IPs {
			ipBlocks = append(ipBlocks, GetIPCidr(ipAddr))
		}
	}

	return membership.revision, ipBlocks, true
}
