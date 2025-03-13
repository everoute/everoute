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

package informer_test

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"
	apiclient "github.com/smartxworks/cloudtower-go-sdk/v2/client"
	"github.com/smartxworks/cloudtower-go-sdk/v2/models"
	"github.com/smartxworks/cloudtower-go-sdk/v2/watchor"

	"github.com/everoute/everoute/plugin/tower/pkg/client"
	"github.com/everoute/everoute/plugin/tower/pkg/informer"
	"github.com/everoute/everoute/plugin/tower/pkg/schema"
)

var (
	eventChanInject chan *models.ResourceChangeEvent
	errorChanInject chan *watchor.ErrorEvent
	mock            *gomonkey.Patches

	crcFactory               *informer.CrcFactory
	eventChanLabel           chan *informer.CrcEvent
	eventChanEverouteCluster chan *informer.CrcEvent
)

const (
	timeout  = time.Second * 10
	interval = time.Millisecond * 250
)

func TestFactorCrc(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Factory CRC test suit")
}

var _ = BeforeSuite(func() {
	eventChanInject = make(chan *models.ResourceChangeEvent, 100)
	errorChanInject = make(chan *watchor.ErrorEvent, 100)

	mock = gomonkey.ApplyFunc(apiclient.NewWithUserConfig,
		func(_ apiclient.ClientConfig, _ apiclient.UserConfig) (*apiclient.Cloudtower, error) {
			By("gomonkey apiclient.NewWithUserConfig")
			return &apiclient.Cloudtower{}, nil
		})
	mock.ApplyMethod(reflect.TypeOf(&watchor.ResourceChangeWatchClient{}), "Start",
		func(m *watchor.ResourceChangeWatchClient, p *watchor.ResourceChangeWatchStartParams) error {
			By("gomonkey watchor.ResourceChangeWatchClient.Start")
			return nil
		})
	mock.ApplyMethod(reflect.TypeOf(&watchor.ResourceChangeWatchClient{}), "Channel",
		func(m *watchor.ResourceChangeWatchClient) <-chan *models.ResourceChangeEvent {
			By("gomonkey watchor.ResourceChangeWatchClient.Channel")
			return eventChanInject
		})
	mock.ApplyMethod(reflect.TypeOf(&watchor.ResourceChangeWatchClient{}), "ErrorChannel",
		func(m *watchor.ResourceChangeWatchClient) <-chan *watchor.ErrorEvent {
			By("gomonkey watchor.ResourceChangeWatchClient.ErrorChannel")
			return errorChanInject
		})

	crcFactory = informer.MustNewCrcFactory(&client.Client{
		UserInfo: &client.UserInfo{},
	})

	eventChanLabel = crcFactory.RegisterEvent(reflect.TypeOf(&schema.Label{}))
	eventChanEverouteCluster = crcFactory.RegisterEvent(reflect.TypeOf(&schema.EverouteCluster{}))

	crcFactory.Start(context.Background().Done())
}, 60)

var _ = AfterSuite(func() {
	By("tearing down the environment")
	mock.Reset()
})

var _ = Describe("Factory CRC", func() {
	Context("MustNewCrcFactory", func() {
		BeforeEach(func() {

		})
		It("should create factory", func() {
			Expect(crcFactory).NotTo(BeNil())
		})

		When("common resource event - label event", func() {
			var label *schema.Label
			var labelNew *schema.Label
			var labelStr []byte
			var labelStrNew []byte
			BeforeEach(func() {
				label = &schema.Label{
					ObjectMeta: schema.ObjectMeta{
						ID: "label1",
					},
					Key:   "key",
					Value: "value",
				}
				labelNew = &schema.Label{
					ObjectMeta: schema.ObjectMeta{
						ID: "label1",
					},
					Key:   "key-new",
					Value: "value-new",
				}
				labelStr, _ = json.Marshal(label)
				labelStrNew, _ = json.Marshal(labelNew)
			})
			It("should process insert event", func() {
				eventChanInject <- &models.ResourceChangeEvent{
					Action:       lo.ToPtr(string(informer.CrcEventInsert)),
					ResourceType: lo.ToPtr("Label"),
					NewValue:     lo.ToPtr(string(labelStrNew)),
				}

				e := getEventChan(eventChanLabel)

				Expect(e.EventType).To(Equal(informer.CrcEventInsert))
				Expect(e.NewObj).NotTo(BeNil())
				obj, ok := e.NewObj.(*schema.Label)
				Expect(ok).To(BeTrue())
				Expect(obj).NotTo(BeNil())
				Expect(obj.ID).To(Equal(labelNew.ID))
				Expect(obj.Key).To(Equal(labelNew.Key))
				Expect(obj.Value).To(Equal(labelNew.Value))
			})
			It("should process update event", func() {
				eventChanInject <- &models.ResourceChangeEvent{
					Action:       lo.ToPtr(string(informer.CrcEventUpdate)),
					ResourceType: lo.ToPtr("Label"),
					OldValue:     lo.ToPtr(string(labelStr)),
					NewValue:     lo.ToPtr(string(labelStrNew)),
				}

				e := getEventChan(eventChanLabel)

				Expect(e.EventType).To(Equal(informer.CrcEventUpdate))
				Expect(e.OldObj).NotTo(BeNil())
				Expect(e.NewObj).NotTo(BeNil())
				obj, ok := e.NewObj.(*schema.Label)
				Expect(ok).To(BeTrue())
				Expect(obj).NotTo(BeNil())
				Expect(obj.ID).To(Equal(labelNew.ID))
				Expect(obj.Key).To(Equal(labelNew.Key))
				Expect(obj.Value).To(Equal(labelNew.Value))
			})
			It("should process delete event", func() {
				eventChanInject <- &models.ResourceChangeEvent{
					Action:       lo.ToPtr(string(informer.CrcEventDelete)),
					ResourceType: lo.ToPtr("Label"),
					OldValue:     lo.ToPtr(string(labelStr)),
				}

				e := getEventChan(eventChanLabel)

				Expect(e.EventType).To(Equal(informer.CrcEventDelete))
				Expect(e.OldObj).NotTo(BeNil())
				obj, ok := e.OldObj.(*schema.Label)
				Expect(ok).To(BeTrue())
				Expect(obj).NotTo(BeNil())
				Expect(obj.ID).To(Equal(label.ID))
			})

			When("process _LabelToVm relation", func() {
				var labelToVm *schema.Relation
				var labelToVmStr []byte
				var labelToVmNew *schema.Relation
				var labelToVmNewStr []byte
				BeforeEach(func() {
					labelToVm = &schema.Relation{
						ObjectMeta: schema.ObjectMeta{
							ID: "label-vm-id-1",
						},
						A: "label1",
						B: "vm1",
					}
					labelToVmNew = &schema.Relation{
						ObjectMeta: schema.ObjectMeta{
							ID: "id1",
						},
						A: "label1",
						B: "vm2",
					}
					labelToVmStr, _ = json.Marshal(labelToVm)
					labelToVmNewStr, _ = json.Marshal(labelToVmNew)
				})
				It("should process insert event", func() {
					eventChanInject <- &models.ResourceChangeEvent{
						Action:       lo.ToPtr(string(informer.CrcEventInsert)),
						ResourceType: lo.ToPtr("_LabelToVm"),
						NewValue:     lo.ToPtr(string(labelToVmStr)),
					}

					e := getEventChan(eventChanLabel)

					Expect(e.EventType).To(Equal(informer.CrcEventUpdate))
					Expect(e.NewObj).NotTo(BeNil())
					obj, ok := e.NewObj.(*schema.Label)
					Expect(ok).To(BeTrue())
					Expect(obj).NotTo(BeNil())
					Expect(obj.ID).To(Equal(labelToVm.A))
				})
				It("should process update event", func() {
					eventChanInject <- &models.ResourceChangeEvent{
						Action:       lo.ToPtr(string(informer.CrcEventUpdate)),
						ResourceType: lo.ToPtr("_LabelToVm"),
						OldValue:     lo.ToPtr(string(labelToVmStr)),
						NewValue:     lo.ToPtr(string(labelToVmNewStr)),
					}

					e := getEventChan(eventChanLabel)

					Expect(e.EventType).To(Equal(informer.CrcEventUpdate))
					Expect(e.NewObj).NotTo(BeNil())
					obj, ok := e.NewObj.(*schema.Label)
					Expect(ok).To(BeTrue())
					Expect(obj).NotTo(BeNil())
					Expect(obj.ID).To(Equal(labelToVm.A))
				})
				It("should process delete event", func() {
					eventChanInject <- &models.ResourceChangeEvent{
						Action:       lo.ToPtr(string(informer.CrcEventDelete)),
						ResourceType: lo.ToPtr("_LabelToVm"),
						OldValue:     lo.ToPtr(string(labelToVmStr)),
					}

					e := getEventChan(eventChanLabel)
					Expect(e.EventType).To(Equal(informer.CrcEventUpdate))
					Expect(e.NewObj).NotTo(BeNil())
					obj, ok := e.NewObj.(*schema.Label)
					Expect(ok).To(BeTrue())
					Expect(obj).NotTo(BeNil())
					Expect(obj.ID).To(Equal(labelToVm.A))
				})
			})
		})

		When("process everouteCluster", func() {
			When("update from elf cluster", func() {
				var cluster *schema.AgentELFCluster
				var clusterStr []byte
				var clusterNew *schema.AgentELFCluster
				var clusterStrNew []byte
				BeforeEach(func() {
					cluster = &schema.AgentELFCluster{
						ObjectMeta: schema.ObjectMeta{
							ID: "cluster1",
						},
						LocalID:            "local-cluster1",
						EverouteClusterRef: schema.ObjectReference{ID: ""},
					}
					clusterNew = &schema.AgentELFCluster{
						ObjectMeta: schema.ObjectMeta{
							ID: "cluster1",
						},
						LocalID:            "local-cluster1",
						EverouteClusterRef: schema.ObjectReference{ID: "everoute-cluster1"},
					}
					clusterStr, _ = json.Marshal(cluster)
					clusterStrNew, _ = json.Marshal(clusterNew)
				})
				It("should process update event", func() {
					eventChanInject <- &models.ResourceChangeEvent{
						Action:       lo.ToPtr(string(informer.CrcEventUpdate)),
						ResourceType: lo.ToPtr("Cluster"),
						OldValue:     lo.ToPtr(string(clusterStr)),
						NewValue:     lo.ToPtr(string(clusterStrNew)),
					}

					e := getEventChan(eventChanEverouteCluster)

					Expect(e.EventType).To(Equal(informer.CrcEventUpdate))
					Expect(e.NewObj).NotTo(BeNil())
					obj, ok := e.NewObj.(*schema.EverouteCluster)
					Expect(ok).To(BeTrue())
					Expect(obj).NotTo(BeNil())
					Expect(obj.ID).To(Equal(clusterNew.EverouteClusterRef.ID))
				})
			})
			When("update from vds", func() {
				var vds *schema.AgentELFVDS
				var vdsStr []byte
				var vdsNew *schema.AgentELFVDS
				var vdsStrNew []byte
				BeforeEach(func() {
					vds = &schema.AgentELFVDS{
						ObjectMeta: schema.ObjectMeta{
							ID: "vds1",
						},
						EverouteClusterRef: schema.ObjectReference{ID: ""},
					}
					vdsNew = &schema.AgentELFVDS{
						ObjectMeta: schema.ObjectMeta{
							ID: "vds1",
						},
						EverouteClusterRef: schema.ObjectReference{ID: "everoute-cluster1"},
					}
					vdsStr, _ = json.Marshal(vds)
					vdsStrNew, _ = json.Marshal(vdsNew)
				})
				It("should process update event", func() {
					eventChanInject <- &models.ResourceChangeEvent{
						Action:       lo.ToPtr(string(informer.CrcEventUpdate)),
						ResourceType: lo.ToPtr("Vds"),
						OldValue:     lo.ToPtr(string(vdsStr)),
						NewValue:     lo.ToPtr(string(vdsStrNew)),
					}

					e := getEventChan(eventChanEverouteCluster)

					Expect(e.EventType).To(Equal(informer.CrcEventUpdate))
					Expect(e.NewObj).NotTo(BeNil())
					obj, ok := e.NewObj.(*schema.EverouteCluster)
					Expect(ok).To(BeTrue())
					Expect(obj).NotTo(BeNil())
					Expect(obj.ID).To(Equal(vdsNew.EverouteClusterRef.ID))
				})
			})
		})
	})
})

func getEventChan(eventChan chan *informer.CrcEvent) *informer.CrcEvent {
	select {
	case e := <-eventChan:
		return e
	case <-time.After(timeout):
		Fail("timeout")
	}
	return nil
}
