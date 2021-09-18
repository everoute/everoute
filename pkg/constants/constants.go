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

package constants

const (
	NormalPolicyRulePriority        = 100
	DefaultPolicyRulePriority       = 70
	GlobalDefaultPolicyRulePriority = 40

	DefaultMaxConcurrentReconciles   = 4
	NumOfRetainedGroupMembersPatches = 3
	DependentsCleanFinalizer         = "finalizer.lynx.smartx.com/dependentsclean"
	OwnerGroupLabelKey               = "label.lynx.smartx.com/ownergroup"
	OwnerPolicyLabelKey              = "label.lynx.smartx.com/ownerpolicy"
	IsGlobalPolicyRuleLabel          = "label.lynx.smartx.com/isglobalpolicy"

	// Tier0 used for isolation policy
	Tier0 = "tier0"
	// Tier1 used for security policy and global policy
	Tier1 = "tier1"
	Tier2 = "tier2"

	SecurityPolicyByEndpointIndex      = "SecurityPolicyByEndpointIndex"
	SecurityPolicyByEndpointGroupIndex = "SecurityPolicyByEndpointGroupIndex"
)
