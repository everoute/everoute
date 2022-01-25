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

package exporter

import (
	"strings"

	"github.com/Shopify/sarama"
	"google.golang.org/protobuf/proto"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/klog"

	"github.com/everoute/everoute/pkg/apis/exporter/v1alpha1"
)

const (
	KafkaFlowTopic         = "flow"
	KafkaSFlowSampleTopic  = "sflow-sample"
	KafkaSFlowCounterTopic = "sflow-counter"
	KafkaOvsFlowTopic      = "ovs-flow"
)

type Uploader interface {
	Flow(msg *v1alpha1.FlowMessage)
	SFlowSample()
	SFlowCounter(msg *v1alpha1.CounterMessage)
	OVSFlow()
}

type KafkaUploader struct {
	Producer sarama.AsyncProducer
	AgentID  string
}

func NewKafkaUploader(hosts string, agentID string, stopChan <-chan struct{}) *KafkaUploader {
	producer, err := sarama.NewAsyncProducer(strings.Split(hosts, ","), sarama.NewConfig())
	if err != nil {
		klog.Fatal(err)
	}

	go func() {
		for {
			select {
			case err := <-producer.Errors():
				klog.Infof("producer error: %s", err)
			case <-stopChan:
				producer.Close()
				return
			}
		}
	}()

	return &KafkaUploader{
		Producer: producer,
		AgentID:  agentID,
	}
}

func (k *KafkaUploader) Flow(msg *v1alpha1.FlowMessage) {
	msg.AgentId = k.AgentID
	k.Send(protoToByte(msg), KafkaFlowTopic)
}
func (k *KafkaUploader) SFlowSample() {

}
func (k *KafkaUploader) SFlowCounter(msg *v1alpha1.CounterMessage) {
	msg.AgentId = k.AgentID
	k.Send(protoToByte(msg), KafkaSFlowCounterTopic)
}
func (k *KafkaUploader) OVSFlow() {

}
func (k *KafkaUploader) Send(data []byte, topic string) {
	k.Producer.Input() <- &sarama.ProducerMessage{
		Topic: topic,
		Key:   sarama.ByteEncoder(uuid.NewUUID()),
		Value: sarama.ByteEncoder(data),
	}
}
func protoToByte(m proto.Message) []byte {
	b, err := proto.Marshal(m)
	if err != nil {
		klog.Error(err)
	}
	return b
}
