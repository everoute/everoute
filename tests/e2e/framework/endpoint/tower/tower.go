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

// todo: generate by tools (any tools could generate client code?)

package tower

import (
	"encoding/json"
	"fmt"
	"reflect"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/everoute/everoute/plugin/tower/pkg/client"
	"github.com/everoute/everoute/plugin/tower/pkg/utils"
)

/*
   createVm(data: VmCreateInput!, effect: CreateVmEffect!): Vm!
   updateVm(data: VmUpdateInput!, where: VmWhereUniqueInput!): Vm
   deleteVm(where: VmWhereUniqueInput!): Vm
*/
func mutationCreateVM(c *client.Client, data *VMCreateInput, effect *CreateVMEffect) (*VM, error) {
	var queryFields = utils.GqlTypeMarshal(reflect.TypeOf(VM{}), nil, true)

	request := client.Request{
		Query: fmt.Sprintf("mutation createVm($data: VmCreateInput!, $effect: CreateVmEffect!) {createVm(data: $data, effect: $effect) %s}", queryFields),
		Variables: map[string]interface{}{
			"data":   data,
			"effect": effect,
		},
	}

	resp, err := c.Query(&request)
	if err != nil || len(resp.Errors) != 0 {
		return nil, fmt.Errorf("mutation from tower, reply: %s, err: %s", resp, err)
	}

	var vm VM
	err = json.Unmarshal(utils.LookupJSONRaw(resp.Data, "createVm"), &vm)
	return &vm, err
}

func mutationUpdateVM(c *client.Client, data *VMUpdateInput, where *VMWhereUniqueInput) (*VM, error) {
	var queryFields = utils.GqlTypeMarshal(reflect.TypeOf(VM{}), nil, true)

	request := client.Request{
		Query: fmt.Sprintf("mutation updateVm($data: VmUpdateInput!, $where: VmWhereUniqueInput!) {updateVm(data: $data, where: $where) %s}", queryFields),
		Variables: map[string]interface{}{
			"data":  data,
			"where": where,
		},
	}

	resp, err := c.Query(&request)
	if err != nil || len(resp.Errors) != 0 {
		return nil, fmt.Errorf("mutation from tower, reply: %s, err: %s", resp, err)
	}

	var vm VM
	err = json.Unmarshal(utils.LookupJSONRaw(resp.Data, "updateVm"), &vm)
	return &vm, err
}

func mutationDeleteVM(c *client.Client, where *VMWhereUniqueInput) (*VM, error) {
	var queryFields = utils.GqlTypeMarshal(reflect.TypeOf(VM{}), nil, true)

	request := client.Request{
		Query: fmt.Sprintf("mutation deleteVM($where: VmWhereUniqueInput!) {deleteVm(where: $where) %s}", queryFields),
		Variables: map[string]interface{}{
			"where": where,
		},
	}

	resp, err := c.Query(&request)
	if err != nil || len(resp.Errors) != 0 {
		return nil, fmt.Errorf("mutation from tower, reply: %s, err: %s", resp, err)
	}

	var vm VM
	err = json.Unmarshal(utils.LookupJSONRaw(resp.Data, "deleteVm"), &vm)
	return &vm, err
}

/*
   createLabel(data: LabelCreateInput!): Label!
   updateLabel(data: LabelUpdateInput!, where: LabelWhereUniqueInput!): Label
   deleteLabel(where: LabelWhereUniqueInput!): Label
*/
func mutationCreateLabel(c *client.Client, data *LabelCreateInput) (*Label, error) {
	var queryFields = utils.GqlTypeMarshal(reflect.TypeOf(Label{}), nil, true)

	request := client.Request{
		Query: fmt.Sprintf("mutation createLabel($data: LabelCreateInput!) {createLabel(data: $data) %s}", queryFields),
		Variables: map[string]interface{}{
			"data": data,
		},
	}

	resp, err := c.Query(&request)
	if err != nil || len(resp.Errors) != 0 {
		return nil, fmt.Errorf("mutation from tower, reply: %s, err: %s", resp, err)
	}

	var label Label
	err = json.Unmarshal(utils.LookupJSONRaw(resp.Data, "createLabel"), &label)
	return &label, err
}

func mutationUpdateLabel(c *client.Client, data *LabelUpdateInput, where *LabelWhereUniqueInput) (*Label, error) {
	var queryFields = utils.GqlTypeMarshal(reflect.TypeOf(Label{}), nil, true)

	request := client.Request{
		Query: fmt.Sprintf("mutation updateLabel($data: LabelUpdateInput!, $where: LabelWhereUniqueInput!) {updateLabel(data: $data, where: $where) %s}", queryFields),
		Variables: map[string]interface{}{
			"data":  data,
			"where": where,
		},
	}

	resp, err := c.Query(&request)
	if err != nil || len(resp.Errors) != 0 {
		return nil, fmt.Errorf("mutation from tower, reply: %s, err: %s", resp, err)
	}

	var label Label
	err = json.Unmarshal(utils.LookupJSONRaw(resp.Data, "updateLabel"), &label)
	return &label, err
}

func mutationDeleteLabel(c *client.Client, where *LabelWhereUniqueInput) (*Label, error) {
	var queryFields = utils.GqlTypeMarshal(reflect.TypeOf(Label{}), nil, true)

	request := client.Request{
		Query: fmt.Sprintf("mutation deleteLabel($where: LabelWhereUniqueInput!) {deleteLabel(where: $where) %s}", queryFields),
		Variables: map[string]interface{}{
			"where": where,
		},
	}

	resp, err := c.Query(&request)
	if err != nil || len(resp.Errors) != 0 {
		return nil, fmt.Errorf("mutation from tower, reply: %s, err: %s", resp, err)
	}

	var label Label
	err = json.Unmarshal(utils.LookupJSONRaw(resp.Data, "deleteLabel"), &label)
	return &label, err
}

/*
   createVlan(data: VlanCreateInput!): Vlan!
*/
func mutationCreateVlan(c *client.Client, data *VlanCreateInput) (*Vlan, error) {
	var queryFields = utils.GqlTypeMarshal(reflect.TypeOf(Vlan{}), nil, true)

	request := client.Request{
		Query: fmt.Sprintf("mutation createVlan($data: VlanCreateInput!) {createVlan(data: $data) %s}", queryFields),
		Variables: map[string]interface{}{
			"data": data,
		},
	}

	resp, err := c.Query(&request)
	if err != nil || len(resp.Errors) != 0 {
		return nil, fmt.Errorf("mutation from tower, reply: %s, err: %s", resp, err)
	}

	var vlan Vlan
	err = json.Unmarshal(utils.LookupJSONRaw(resp.Data, "createVlan"), &vlan)
	return &vlan, err
}

/*
   vm(where: VmWhereUniqueInput!): Vm
   vms: [Vm!]!
*/
func queryVM(c *client.Client, where *VMWhereUniqueInput) (*VM, error) {
	var queryFields = utils.GqlTypeMarshal(reflect.TypeOf(VM{}), nil, true)

	request := client.Request{
		Query: fmt.Sprintf("query vm($where: VmWhereUniqueInput!) {vm(where: $where) %s}", queryFields),
		Variables: map[string]interface{}{
			"where": where,
		},
	}

	resp, err := c.Query(&request)
	if err != nil || len(resp.Errors) != 0 {
		return nil, fmt.Errorf("mutation from tower, reply: %s, err: %s", resp, err)
	}

	data := utils.LookupJSONRaw(resp.Data, "vm")
	if string(data) == "null" {
		return nil, errors.NewNotFound(schema.GroupResource{Group: "tower.smartx.com", Resource: "vm"}, *where.ID)
	}

	var vm VM
	err = json.Unmarshal(data, &vm)
	return &vm, err
}

func queryVMs(c *client.Client, where *VMWhereInput) ([]VM, error) {
	var queryFields = utils.GqlTypeMarshal(reflect.TypeOf([]VM{}), nil, true)

	request := client.Request{
		Query: fmt.Sprintf("query vms($where: VmWhereInput) {vms(where: $where) %s}", queryFields),
		Variables: map[string]interface{}{
			"where": where,
		},
	}

	resp, err := c.Query(&request)
	if err != nil || len(resp.Errors) != 0 {
		return nil, fmt.Errorf("mutation from tower, reply: %s, err: %s", resp, err)
	}

	var vm []VM
	err = json.Unmarshal(utils.LookupJSONRaw(resp.Data, "vms"), &vm)
	return vm, err
}

/*
   label(where: LabelWhereUniqueInput!): Label
   labels: [Label!]!
*/
func queryLabel(c *client.Client, where *LabelWhereUniqueInput) (*Label, error) {
	var queryFields = utils.GqlTypeMarshal(reflect.TypeOf(Label{}), nil, true)

	request := client.Request{
		Query: fmt.Sprintf("query label($where: LabelWhereUniqueInput!) {label(where: $where) %s}", queryFields),
		Variables: map[string]interface{}{
			"where": where,
		},
	}

	resp, err := c.Query(&request)
	if err != nil || len(resp.Errors) != 0 {
		return nil, fmt.Errorf("mutation from tower, reply: %s, err: %s", resp, err)
	}

	data := utils.LookupJSONRaw(resp.Data, "label")
	if string(data) == "null" {
		return nil, errors.NewNotFound(schema.GroupResource{Group: "tower.smartx.com", Resource: "label"}, *where.ID)
	}

	var label Label
	err = json.Unmarshal(data, &label)
	return &label, err
}

func queryLabels(c *client.Client) ([]Label, error) {
	var queryFields = utils.GqlTypeMarshal(reflect.TypeOf([]Label{}), nil, true)

	request := client.Request{
		Query:     fmt.Sprintf("query labels {labels %s}", queryFields),
		Variables: map[string]interface{}{},
	}

	resp, err := c.Query(&request)
	if err != nil || len(resp.Errors) != 0 {
		return nil, fmt.Errorf("mutation from tower, reply: %s, err: %s", resp, err)
	}

	var labels []Label
	err = json.Unmarshal(utils.LookupJSONRaw(resp.Data, "labels"), &labels)
	return labels, err
}

/*
   vlan(where: VlanWhereUniqueInput!): Vlan
   vlans: [Vlan!]
*/
func queryVlan(c *client.Client, where *VlanWhereUniqueInput) (*Vlan, error) {
	var queryFields = utils.GqlTypeMarshal(reflect.TypeOf(Vlan{}), nil, true)

	request := client.Request{
		Query: fmt.Sprintf("query vlan($where: VlanWhereUniqueInput!) {vlan(where: $where) %s}", queryFields),
		Variables: map[string]interface{}{
			"where": where,
		},
	}

	resp, err := c.Query(&request)
	if err != nil || len(resp.Errors) != 0 {
		return nil, fmt.Errorf("mutation from tower, reply: %s, err: %s", resp, err)
	}

	data := utils.LookupJSONRaw(resp.Data, "vlan")
	if string(data) == "null" {
		return nil, errors.NewNotFound(schema.GroupResource{Group: "tower.smartx.com", Resource: "vlan"}, *where.ID)
	}

	var vlan Vlan
	err = json.Unmarshal(data, &vlan)
	return &vlan, err
}

func queryVlans(c *client.Client) ([]Vlan, error) {
	var queryFields = utils.GqlTypeMarshal(reflect.TypeOf([]Vlan{}), nil, true)

	request := client.Request{
		Query:     fmt.Sprintf("query vlans {vlans %s}", queryFields),
		Variables: map[string]interface{}{},
	}

	resp, err := c.Query(&request)
	if err != nil || len(resp.Errors) != 0 {
		return nil, fmt.Errorf("mutation from tower, reply: %s, err: %s", resp, err)
	}

	var vlans []Vlan
	err = json.Unmarshal(utils.LookupJSONRaw(resp.Data, "vlans"), &vlans)
	return vlans, err
}

/*
   vmTemplate(where: VmTemplateWhereUniqueInput!): VmTemplate
*/
func queryVMTemplate(c *client.Client, where *VMTemplateWhereUniqueInput) (*VMTemplate, error) {
	var queryFields = utils.GqlTypeMarshal(reflect.TypeOf(VMTemplate{}), nil, true)

	request := client.Request{
		Query: fmt.Sprintf("query vmTemplate($where: VmTemplateWhereUniqueInput!) {vmTemplate(where: $where) %s}", queryFields),
		Variables: map[string]interface{}{
			"where": where,
		},
	}

	resp, err := c.Query(&request)
	if err != nil || len(resp.Errors) != 0 {
		return nil, fmt.Errorf("mutation from tower, reply: %s, err: %s", resp, err)
	}

	data := utils.LookupJSONRaw(resp.Data, "vmTemplate")
	if string(data) == "null" {
		return nil, errors.NewNotFound(schema.GroupResource{Group: "tower.smartx.com", Resource: "vmTemplate"}, *where.ID)
	}

	var vmTemplate VMTemplate
	err = json.Unmarshal(data, &vmTemplate)
	return &vmTemplate, err
}

/*
   host(where: HostWhereUniqueInput!): Host
*/
func queryHost(c *client.Client, where *HostWhereUniqueInput) (*Host, error) {
	var queryFields = utils.GqlTypeMarshal(reflect.TypeOf(Host{}), nil, true)

	request := client.Request{
		Query: fmt.Sprintf("query host($where: HostWhereUniqueInput!) {host(where: $where) %s}", queryFields),
		Variables: map[string]interface{}{
			"where": where,
		},
	}

	resp, err := c.Query(&request)
	if err != nil || len(resp.Errors) != 0 {
		return nil, fmt.Errorf("mutation from tower, reply: %s, err: %s", resp, err)
	}

	data := utils.LookupJSONRaw(resp.Data, "host")
	if string(data) == "null" {
		return nil, errors.NewNotFound(schema.GroupResource{Group: "tower.smartx.com", Resource: "host"}, *where.ID)
	}

	var host Host
	err = json.Unmarshal(data, &host)
	return &host, err
}
