package cache

import (
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"

	groupv1alpha1 "github.com/everoute/everoute/pkg/apis/group/v1alpha1"
	"github.com/everoute/everoute/pkg/types"
)

const (
	GroupName     = "group"
	PatchRevision = 1
	Agent1        = "agent1"
	Agent2        = "agent2"
	Agent3        = "agent3"
	IP1           = "10.10.11.12"
	IP2           = "10.10.11.13"
	IP3           = "10.10.11.14"
)

var (
	ep1Ref = groupv1alpha1.EndpointReference{
		ExternalIDName:  "iface-id",
		ExternalIDValue: "ep1",
	}

	ep2Ref = groupv1alpha1.EndpointReference{
		ExternalIDName:  "iface-id",
		ExternalIDValue: "ep2",
	}
)

func getTestCache() *GroupCache {
	cache := NewGroupCache()

	members := &groupMembership{
		name:      GroupName,
		revision:  PatchRevision,
		endpoints: make(map[groupv1alpha1.EndpointReference]groupv1alpha1.GroupMember),
	}
	members.endpoints[ep1Ref] = groupv1alpha1.GroupMember{
		EndpointReference: ep1Ref,
		EndpointAgent:     []string{Agent1, Agent2},
		IPs:               []types.IPAddress{types.IPAddress(IP1), types.IPAddress(IP2)},
	}
	members.endpoints[ep2Ref] = groupv1alpha1.GroupMember{
		EndpointReference: ep2Ref,
		EndpointAgent:     []string{Agent3},
		IPs:               []types.IPAddress{types.IPAddress(IP3)},
	}
	ep3Ref := groupv1alpha1.EndpointReference{
		ExternalIDName:  "iface-id",
		ExternalIDValue: "ep3",
	}
	members.endpoints[ep3Ref] = groupv1alpha1.GroupMember{
		EndpointReference: ep3Ref,
		EndpointAgent:     []string{Agent1},
		IPs:               []types.IPAddress{types.IPAddress("192.168.11.12"), types.IPAddress(IP3)},
	}
	cache.members[GroupName] = members
	return cache
}

func groupPatchEqual(p1, p2 GroupPatch) bool {
	if p1.GroupName != p2.GroupName {
		return false
	}
	if p1.Revision != p2.Revision {
		return false
	}

	if len(p1.Add) != len(p2.Add) {
		return false
	}

	for k, v := range p1.Add {
		p2v, ok := p2.Add[k]
		if !ok {
			return false
		}
		if !v.AgentRef.Equal(p2v.AgentRef) {
			return false
		}
	}

	if len(p1.Del) != len(p2.Del) {
		return false
	}

	for k, v := range p1.Del {
		p2v, ok := p2.Del[k]
		if !ok {
			return false
		}
		if !v.AgentRef.Equal(p2v.AgentRef) {
			return false
		}
	}

	return true
}

func TestNextPatch(t *testing.T) {
	tests := []struct {
		name string

		addPatch groupv1alpha1.GroupMembersPatch

		groupPatchAddIPs      []string
		groupPatchAddIPBlocks []IPBlockItem
		groupPatchDelIPs      []string
		groupPatchDelIPBlocks []IPBlockItem
	}{
		{
			name: "add member with new ip",
			addPatch: groupv1alpha1.GroupMembersPatch{
				AppliedToGroupMembers: groupv1alpha1.GroupMembersReference{
					Name:     GroupName,
					Revision: PatchRevision,
				},
				AddedGroupMembers: []groupv1alpha1.GroupMember{{
					EndpointReference: groupv1alpha1.EndpointReference{
						ExternalIDName:  "iface-id",
						ExternalIDValue: "ep-add",
					},
					EndpointAgent: []string{Agent1},
					IPs:           []types.IPAddress{types.IPAddress("133.133.12.12")},
				}},
			},
			groupPatchAddIPs: []string{"133.133.12.12"},
			groupPatchAddIPBlocks: []IPBlockItem{{
				AgentRef: sets.NewString(Agent1),
			}},
		}, {
			name: "add member with exists ip to add agent",
			addPatch: groupv1alpha1.GroupMembersPatch{
				AppliedToGroupMembers: groupv1alpha1.GroupMembersReference{
					Name:     GroupName,
					Revision: PatchRevision,
				},
				AddedGroupMembers: []groupv1alpha1.GroupMember{{
					EndpointReference: groupv1alpha1.EndpointReference{
						ExternalIDName:  "iface-id",
						ExternalIDValue: "ep-add",
					},
					EndpointAgent: []string{"add-agent"},
					IPs:           []types.IPAddress{types.IPAddress(IP1)},
				}},
			},
			groupPatchAddIPs: []string{IP1},
			groupPatchAddIPBlocks: []IPBlockItem{{
				AgentRef: sets.NewString("add-agent", Agent1, Agent2),
			}},
			groupPatchDelIPs: []string{IP1},
			groupPatchDelIPBlocks: []IPBlockItem{{
				AgentRef: sets.NewString(Agent1, Agent2),
			}},
		}, {
			name: "add member with exists ip has none agent",
			addPatch: groupv1alpha1.GroupMembersPatch{
				AppliedToGroupMembers: groupv1alpha1.GroupMembersReference{
					Name:     GroupName,
					Revision: PatchRevision,
				},
				AddedGroupMembers: []groupv1alpha1.GroupMember{{
					EndpointReference: groupv1alpha1.EndpointReference{
						ExternalIDName:  "iface-id",
						ExternalIDValue: "ep-add",
					},
					EndpointAgent: []string{},
					IPs:           []types.IPAddress{types.IPAddress(IP1)},
				}},
			},
			groupPatchAddIPs: []string{IP1},
			groupPatchAddIPBlocks: []IPBlockItem{{
				AgentRef: sets.NewString(),
			}},
			groupPatchDelIPs: []string{IP1},
			groupPatchDelIPBlocks: []IPBlockItem{{
				AgentRef: sets.NewString(Agent1, Agent2),
			}},
		}, {
			name: "update member to delete ip",
			addPatch: groupv1alpha1.GroupMembersPatch{
				AppliedToGroupMembers: groupv1alpha1.GroupMembersReference{
					Name:     GroupName,
					Revision: PatchRevision,
				},
				UpdatedGroupMembers: []groupv1alpha1.GroupMember{{
					EndpointReference: ep1Ref,
					EndpointAgent:     []string{Agent1, Agent2},
					IPs:               []types.IPAddress{types.IPAddress(IP1)},
				}},
			},
			groupPatchAddIPs: []string{IP1},
			groupPatchAddIPBlocks: []IPBlockItem{{
				AgentRef: sets.NewString(Agent1, Agent2),
			}},
			groupPatchDelIPs: []string{IP1, IP2},
			groupPatchDelIPBlocks: []IPBlockItem{{
				AgentRef: sets.NewString(Agent1, Agent2),
			}, {
				AgentRef: sets.NewString(Agent1, Agent2),
			}},
		}, {
			name: "update member to add ip",
			addPatch: groupv1alpha1.GroupMembersPatch{
				AppliedToGroupMembers: groupv1alpha1.GroupMembersReference{
					Name:     GroupName,
					Revision: PatchRevision,
				},
				UpdatedGroupMembers: []groupv1alpha1.GroupMember{{
					EndpointReference: ep1Ref,
					EndpointAgent:     []string{Agent1, Agent2},
					IPs:               []types.IPAddress{types.IPAddress(IP1), types.IPAddress(IP2), types.IPAddress("124.124.11.11")},
				}},
			},
			groupPatchAddIPs: []string{IP1, IP2, "124.124.11.11"},
			groupPatchAddIPBlocks: []IPBlockItem{{
				AgentRef: sets.NewString(Agent1, Agent2),
			}, {
				AgentRef: sets.NewString(Agent1, Agent2),
			}, {
				AgentRef: sets.NewString(Agent1, Agent2),
			}},
			groupPatchDelIPs: []string{IP1, IP2},
			groupPatchDelIPBlocks: []IPBlockItem{{
				AgentRef: sets.NewString(Agent1, Agent2),
			}, {
				AgentRef: sets.NewString(Agent1, Agent2),
			}},
		}, {
			name: "update member to update ip agentRef",
			addPatch: groupv1alpha1.GroupMembersPatch{
				AppliedToGroupMembers: groupv1alpha1.GroupMembersReference{
					Name:     GroupName,
					Revision: PatchRevision,
				},
				UpdatedGroupMembers: []groupv1alpha1.GroupMember{{
					EndpointReference: ep1Ref,
					EndpointAgent:     []string{Agent1},
					IPs:               []types.IPAddress{types.IPAddress(IP1), types.IPAddress(IP2)},
				}},
			},
			groupPatchAddIPs: []string{IP1, IP2},
			groupPatchAddIPBlocks: []IPBlockItem{{
				AgentRef: sets.NewString(Agent1),
			}, {
				AgentRef: sets.NewString(Agent1),
			}},
			groupPatchDelIPs: []string{IP1, IP2},
			groupPatchDelIPBlocks: []IPBlockItem{{
				AgentRef: sets.NewString(Agent1, Agent2),
			}, {
				AgentRef: sets.NewString(Agent1, Agent2),
			}},
		}, {
			name: "delete member to delete ip",
			addPatch: groupv1alpha1.GroupMembersPatch{
				AppliedToGroupMembers: groupv1alpha1.GroupMembersReference{
					Name:     GroupName,
					Revision: PatchRevision,
				},
				RemovedGroupMembers: []groupv1alpha1.GroupMember{{
					EndpointReference: ep1Ref,
					EndpointAgent:     []string{Agent1, Agent2},
					IPs:               []types.IPAddress{types.IPAddress(IP1), types.IPAddress(IP2)},
				}},
			},
			groupPatchDelIPs: []string{IP1, IP2},
			groupPatchDelIPBlocks: []IPBlockItem{{
				AgentRef: sets.NewString(Agent1, Agent2),
			}, {
				AgentRef: sets.NewString(Agent1, Agent2),
			}},
		}, {
			name: "delete member to update ip agentRef",
			addPatch: groupv1alpha1.GroupMembersPatch{
				AppliedToGroupMembers: groupv1alpha1.GroupMembersReference{
					Name:     GroupName,
					Revision: PatchRevision,
				},
				RemovedGroupMembers: []groupv1alpha1.GroupMember{{
					EndpointReference: ep2Ref,
					EndpointAgent:     []string{Agent3},
					IPs:               []types.IPAddress{types.IPAddress(IP3)},
				}},
			},
			groupPatchAddIPs: []string{IP3},
			groupPatchAddIPBlocks: []IPBlockItem{{
				AgentRef: sets.NewString(Agent1),
			}},
			groupPatchDelIPs: []string{IP3},
			groupPatchDelIPBlocks: []IPBlockItem{{
				AgentRef: sets.NewString(Agent1, Agent3),
			}},
		},
	}

	for i := range tests {
		tdata := tests[i]
		cache := getTestCache()
		cache.AddPatch(&tdata.addPatch)
		expect := GroupPatch{
			GroupName: GroupName,
			Revision:  PatchRevision,
			Add:       make(map[string]*IPBlockItem),
			Del:       make(map[string]*IPBlockItem),
		}
		for i, v := range tdata.groupPatchAddIPs {
			expect.Add[v+"/32"] = &tdata.groupPatchAddIPBlocks[i]
		}
		for i, v := range tdata.groupPatchDelIPs {
			expect.Del[v+"/32"] = &tdata.groupPatchDelIPBlocks[i]
		}

		res := cache.NextPatch(GroupName)
		if !groupPatchEqual(*res, expect) {
			t.Errorf("test %s failed, expect is %v, real is %v", tdata.name, expect, *res)
		}
	}
}
