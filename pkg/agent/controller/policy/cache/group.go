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

package cache

import (
	"sync"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog"

	groupv1alpha1 "github.com/everoute/everoute/pkg/apis/group/v1alpha1"
)

// GroupCache cache GroupMembers, it's thread safe.
type GroupCache struct {
	lock sync.RWMutex

	members map[string][]groupv1alpha1.GroupMember
}

// NewGroupCache return a new GroupCache.
func NewGroupCache() *GroupCache {
	return &GroupCache{
		members: make(map[string][]groupv1alpha1.GroupMember),
	}
}

// UpdateGroupMembership add or update GroupMembers to cache.
func (cache *GroupCache) UpdateGroupMembership(members *groupv1alpha1.GroupMembers) {
	cache.lock.Lock()
	defer cache.lock.Unlock()

	cache.members[members.Name] = append([]groupv1alpha1.GroupMember{}, members.GroupMembers...)
}

// DelGroupMembership removed GroupMembers and it's patches from cache.
func (cache *GroupCache) DelGroupMembership(groupName string) {
	cache.lock.Lock()
	defer cache.lock.Unlock()

	delete(cache.members, groupName)
}

// ListGroupIPBlocks return a list of IPBlocks of the group.
func (cache *GroupCache) ListGroupIPBlocks(groupName string) (map[string]*IPBlockItem, bool) {
	cache.lock.RLock()
	defer cache.lock.RUnlock()

	memberships, ok := cache.members[groupName]
	if !ok {
		return nil, false
	}
	return GroupMembersToIPBlocks(memberships), true
}

func GroupMembersToIPBlocks(members []groupv1alpha1.GroupMember) map[string]*IPBlockItem {
	res := make(map[string]*IPBlockItem)
	if len(members) == 0 {
		return res
	}
	for _, member := range members {
		if len(member.IPs) == 0 {
			klog.V(2).Infof("GroupMember with reference %v has no IPs", member.EndpointReference)
			continue
		}

		for _, ipAddr := range member.IPs {
			ipNetStr := GetIPCidr(ipAddr)
			if _, ok := res[ipNetStr]; !ok {
				res[ipNetStr] = NewIPBlockItem()
				res[ipNetStr].AgentRef.Insert(member.EndpointAgent...)
			} else {
				if res[ipNetStr].AgentRef.Len() == 0 || len(member.EndpointAgent) == 0 {
					res[ipNetStr].AgentRef = sets.NewString()
				} else {
					res[ipNetStr].AgentRef.Insert(member.EndpointAgent...)
				}
			}
			res[ipNetStr].Ports = AppendIPBlockPorts(res[ipNetStr].Ports, member.Ports)
		}
	}
	return res
}
