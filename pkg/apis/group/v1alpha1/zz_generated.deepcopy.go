//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
Copyright The Everoute Authors.

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

// Code generated by deepcopy-gen. DO NOT EDIT.

package v1alpha1

import (
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"

	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	labels "github.com/everoute/everoute/pkg/labels"
	types "github.com/everoute/everoute/pkg/types"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EndpointGroup) DeepCopyInto(out *EndpointGroup) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EndpointGroup.
func (in *EndpointGroup) DeepCopy() *EndpointGroup {
	if in == nil {
		return nil
	}
	out := new(EndpointGroup)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *EndpointGroup) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EndpointGroupList) DeepCopyInto(out *EndpointGroupList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]EndpointGroup, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EndpointGroupList.
func (in *EndpointGroupList) DeepCopy() *EndpointGroupList {
	if in == nil {
		return nil
	}
	out := new(EndpointGroupList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *EndpointGroupList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EndpointGroupSpec) DeepCopyInto(out *EndpointGroupSpec) {
	*out = *in
	if in.EndpointSelector != nil {
		in, out := &in.EndpointSelector, &out.EndpointSelector
		*out = new(labels.Selector)
		(*in).DeepCopyInto(*out)
	}
	if in.NamespaceSelector != nil {
		in, out := &in.NamespaceSelector, &out.NamespaceSelector
		*out = new(v1.LabelSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.Namespace != nil {
		in, out := &in.Namespace, &out.Namespace
		*out = new(string)
		**out = **in
	}
	if in.Endpoint != nil {
		in, out := &in.Endpoint, &out.Endpoint
		*out = new(securityv1alpha1.NamespacedName)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EndpointGroupSpec.
func (in *EndpointGroupSpec) DeepCopy() *EndpointGroupSpec {
	if in == nil {
		return nil
	}
	out := new(EndpointGroupSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *EndpointReference) DeepCopyInto(out *EndpointReference) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new EndpointReference.
func (in *EndpointReference) DeepCopy() *EndpointReference {
	if in == nil {
		return nil
	}
	out := new(EndpointReference)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GroupMember) DeepCopyInto(out *GroupMember) {
	*out = *in
	out.EndpointReference = in.EndpointReference
	if in.EndpointAgent != nil {
		in, out := &in.EndpointAgent, &out.EndpointAgent
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.IPs != nil {
		in, out := &in.IPs, &out.IPs
		*out = make([]types.IPAddress, len(*in))
		copy(*out, *in)
	}
	if in.Ports != nil {
		in, out := &in.Ports, &out.Ports
		*out = make([]securityv1alpha1.NamedPort, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GroupMember.
func (in *GroupMember) DeepCopy() *GroupMember {
	if in == nil {
		return nil
	}
	out := new(GroupMember)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GroupMembers) DeepCopyInto(out *GroupMembers) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	if in.GroupMembers != nil {
		in, out := &in.GroupMembers, &out.GroupMembers
		*out = make([]GroupMember, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GroupMembers.
func (in *GroupMembers) DeepCopy() *GroupMembers {
	if in == nil {
		return nil
	}
	out := new(GroupMembers)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *GroupMembers) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GroupMembersList) DeepCopyInto(out *GroupMembersList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]GroupMembers, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GroupMembersList.
func (in *GroupMembersList) DeepCopy() *GroupMembersList {
	if in == nil {
		return nil
	}
	out := new(GroupMembersList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *GroupMembersList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GroupMembersPatch) DeepCopyInto(out *GroupMembersPatch) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.AppliedToGroupMembers = in.AppliedToGroupMembers
	if in.AddedGroupMembers != nil {
		in, out := &in.AddedGroupMembers, &out.AddedGroupMembers
		*out = make([]GroupMember, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.UpdatedGroupMembers != nil {
		in, out := &in.UpdatedGroupMembers, &out.UpdatedGroupMembers
		*out = make([]GroupMember, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.RemovedGroupMembers != nil {
		in, out := &in.RemovedGroupMembers, &out.RemovedGroupMembers
		*out = make([]GroupMember, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GroupMembersPatch.
func (in *GroupMembersPatch) DeepCopy() *GroupMembersPatch {
	if in == nil {
		return nil
	}
	out := new(GroupMembersPatch)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *GroupMembersPatch) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GroupMembersPatchList) DeepCopyInto(out *GroupMembersPatchList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]GroupMembersPatch, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GroupMembersPatchList.
func (in *GroupMembersPatchList) DeepCopy() *GroupMembersPatchList {
	if in == nil {
		return nil
	}
	out := new(GroupMembersPatchList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *GroupMembersPatchList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GroupMembersReference) DeepCopyInto(out *GroupMembersReference) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GroupMembersReference.
func (in *GroupMembersReference) DeepCopy() *GroupMembersReference {
	if in == nil {
		return nil
	}
	out := new(GroupMembersReference)
	in.DeepCopyInto(out)
	return out
}
