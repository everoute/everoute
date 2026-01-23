/*
Copyright 2025 The Everoute Authors.

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

package informer

import (
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/samber/lo"
	apiclient "github.com/smartxworks/cloudtower-go-sdk/v2/client"
	resource_change_client "github.com/smartxworks/cloudtower-go-sdk/v2/client/resource_change"
	"github.com/smartxworks/cloudtower-go-sdk/v2/models"
	watchor "github.com/smartxworks/cloudtower-go-sdk/v2/watchor"
	"k8s.io/klog/v2"

	"github.com/everoute/everoute/plugin/tower/pkg/client"
	"github.com/everoute/everoute/plugin/tower/pkg/schema"
)

const crcEventChanMax = 100

type CrcFactory struct {
	towerclient *apiclient.Cloudtower
	crcw        *watchor.ResourceChangeWatchClient

	eventOutputMap map[reflect.Type]chan *CrcEvent
}

func MustNewCrcFactory(c *client.Client) *CrcFactory {
	var err error
	factory := &CrcFactory{
		eventOutputMap: map[reflect.Type]chan *CrcEvent{},
	}

	host := strings.TrimPrefix(c.URL, "https://")
	host = strings.TrimSuffix(host, "/api")

	factory.towerclient, err = apiclient.NewWithUserConfig(apiclient.ClientConfig{
		Host:     host,
		BasePath: "v2/api",
		Schemes:  []string{"http"},
	}, apiclient.UserConfig{
		Name:     c.UserInfo.Username,
		Password: c.UserInfo.Password,
		Source:   models.UserSource(c.UserInfo.Source),
	})

	if err != nil {
		klog.Fatalln("fail to init api client", err)
	}

	var options resource_change_client.ClientOption = func(op *runtime.ClientOperation) {
		op.AuthInfo = httptransport.BasicAuth(c.APIUsername, c.APIPassword)
	}

	factory.crcw, err = watchor.NewResourceChangeWatchClient(&watchor.NewResourceChangeWatchClientParams{
		Client:          factory.towerclient,
		ResourceID:      nil,
		PollingInterval: 10 * time.Second,
		ClientOptions:   options,
		ResourceTypes: []string{
			"Vm",
			// "VmNic",
			// "Vlan",
			"Label",
			"_LabelToVm",
			"EverouteCluster",
			"Cluster",
			"Vds",
			"SecurityPolicy",
			"IsolationPolicy",
			"SecurityGroup",
			// "_SecurityGroupToVm",
			"NetworkPolicyRuleService",
		},
	})

	if err != nil {
		klog.Fatalln("fail to init crc client", err)
	}

	return factory
}

func (f *CrcFactory) RegisterEvent(objType reflect.Type) chan *CrcEvent {
	klog.Infof("register crc event for type %s", objType)

	if f.eventOutputMap == nil {
		// only for testcases
		f.eventOutputMap = map[reflect.Type]chan *CrcEvent{}
	}

	out := make(chan *CrcEvent, crcEventChanMax)
	f.eventOutputMap[objType] = out

	return out
}

func (f *CrcFactory) getSchemaObject(resourceType string) schema.Object {
	switch resourceType {
	case "Vm":
		return &schema.VM{}
	case "VmNic":
		return &schema.VMNic{}
	case "Cluster":
		return &schema.AgentELFCluster{}
	case "Vds":
		return &schema.AgentELFVDS{}
	case "Vlan":
		return &schema.Vlan{}
	case "Label":
		return &schema.Label{}
	case "EverouteCluster":
		return &schema.EverouteCluster{}
	case "SecurityPolicy":
		return &schema.SecurityPolicy{}
	case "IsolationPolicy":
		return &schema.IsolationPolicy{}
	case "SecurityGroup":
		return &schema.SecurityGroup{}
	case "NetworkPolicyRuleService":
		return &schema.NetworkPolicyRuleService{}
	case "_LabelToVm", "_SecurityGroupToVm":
		return &schema.Relation{}
	default:
		return nil
	}
}

func (f *CrcFactory) convert(resourceType string, obj string) schema.Object {
	var targetObj = f.getSchemaObject(resourceType)

	if err := json.Unmarshal([]byte(obj), targetObj); err != nil {
		return nil
	}

	return targetObj
}

func (f *CrcFactory) processLabelToVM(oldObj, newObj schema.Object) {
	if v, ok := oldObj.(*schema.Relation); ok && v.A != "" {
		f.eventOutput(&schema.Label{}, CrcEventUpdate, nil, &schema.Label{ObjectMeta: schema.ObjectMeta{ID: v.A}})
	}
	if v, ok := newObj.(*schema.Relation); ok && v.A != "" {
		f.eventOutput(&schema.Label{}, CrcEventUpdate, nil, &schema.Label{ObjectMeta: schema.ObjectMeta{ID: v.A}})
	}
}

func (f *CrcFactory) processCluster(oldObj, newObj schema.Object) {
	if v, ok := oldObj.(*schema.AgentELFCluster); ok && v.ID != "" && v.EverouteClusterRef.ID != "" {
		f.eventOutput(&schema.EverouteCluster{}, CrcEventUpdate, nil,
			&schema.EverouteCluster{ObjectMeta: schema.ObjectMeta{ID: v.EverouteClusterRef.ID}})
	}
	if v, ok := newObj.(*schema.AgentELFCluster); ok && v.ID != "" && v.EverouteClusterRef.ID != "" {
		f.eventOutput(&schema.EverouteCluster{}, CrcEventUpdate, nil,
			&schema.EverouteCluster{ObjectMeta: schema.ObjectMeta{ID: v.EverouteClusterRef.ID}})
	}
}

func (f *CrcFactory) processVds(oldObj, newObj schema.Object) {
	if v, ok := oldObj.(*schema.AgentELFVDS); ok && v.ID != "" && v.EverouteClusterRef.ID != "" {
		f.eventOutput(&schema.EverouteCluster{}, CrcEventUpdate, nil,
			&schema.EverouteCluster{ObjectMeta: schema.ObjectMeta{ID: v.EverouteClusterRef.ID}})
	}
	if v, ok := newObj.(*schema.AgentELFVDS); ok && v.ID != "" && v.EverouteClusterRef.ID != "" {
		f.eventOutput(&schema.EverouteCluster{}, CrcEventUpdate, nil,
			&schema.EverouteCluster{ObjectMeta: schema.ObjectMeta{ID: v.EverouteClusterRef.ID}})
	}
}

func (f *CrcFactory) eventHandler(event *models.ResourceChangeEvent) {
	klog.V(4).Infof("crc eventHandler %s %s old: %+v new: %+v", *event.Action, *event.ResourceType, lo.FromPtr(event.OldValue), lo.FromPtr(event.NewValue))

	var oldObj, newObj schema.Object
	if event.OldValue != nil {
		oldObj = f.convert(*event.ResourceType, *event.OldValue)
	}
	if event.NewValue != nil {
		newObj = f.convert(*event.ResourceType, *event.NewValue)
	}

	/*
		 * resource synced from fisheye will be
		 * UPDATE OldValue=NewValue
		if event.OldValue != nil && event.NewValue != nil {
			if reflect.DeepEqual(oldObj, newObj) {
				return
			}
		}
	*/

	// handler relation table first
	switch *event.ResourceType {
	case "_LabelToVm":
		f.processLabelToVM(oldObj, newObj)
	case "Cluster":
		f.processCluster(oldObj, newObj)
	case "Vds":
		f.processVds(oldObj, newObj)
	default:
		f.eventOutput(f.getSchemaObject(*event.ResourceType), CrcEventType(*event.Action), oldObj, newObj)
	}
}

func (f *CrcFactory) eventOutput(obj schema.Object, eventType CrcEventType, oldObj, newObj schema.Object) {
	if c, ok := f.eventOutputMap[reflect.TypeOf(obj)]; ok {
		event := &CrcEvent{
			EventType: eventType,
			OldObj:    oldObj,
			NewObj:    newObj,
		}
		maxRetry := 20
		for {
			select {
			case c <- event:
				return
			default:
				klog.Errorf("crc event %s output chan is full, retry after 1 s", reflect.TypeOf(obj))
				time.Sleep(1 * time.Second)
				maxRetry--
				if maxRetry <= 0 {
					klog.Errorf("fail to write crc event %s output chan, drop event %+v", reflect.TypeOf(obj), event)
					return
				}
			}
		}
	}
}

func (f *CrcFactory) Start(stopCh <-chan struct{}) {
	crcwLoop := func() {
		err := f.crcw.Start(&watchor.ResourceChangeWatchStartParams{
			StartRevision: nil,
		})

		if err != nil {
			klog.Fatalln(err)
		}

		klog.Infoln("crc factory start")

		for {
			select {
			case err := <-f.crcw.ErrorChannel():
				if err.CompactRevision != nil {
					klog.Fatalf("crc event missed, compacted error : %v, compacted revision: %v\n", err, *err.CompactRevision)
				} else if err.Err != nil {
					klog.Errorf("crc error event: %s\n", err.Err.Error())
					if err.Type == watchor.ErrorEventTypeUnsupported {
						// after unsupported error, crc will stop event loop
						return
					}
				}
			case warning := <-f.crcw.WarningChannel():
				if warning.Err != nil {
					klog.Warningf("crc warning event %s\n", warning.Err.Error())
				}
			case event := <-f.crcw.Channel():
				f.eventHandler(event)
			case <-stopCh:
				return
			}
		}
	}

	go func() {
		for {
			crcwLoop()
			// crcwLoop will return when crc not supported
			// restart after 10 minutes for tower upgrade
			time.Sleep(10 * time.Minute)
		}
	}()
}

type CrcEventType string

const (
	CrcEventInsert CrcEventType = "INSERT"
	CrcEventUpdate CrcEventType = "UPDATE"
	CrcEventDelete CrcEventType = "DELETE"
)

type CrcEvent struct {
	EventType CrcEventType
	OldObj    schema.Object
	NewObj    schema.Object
}
