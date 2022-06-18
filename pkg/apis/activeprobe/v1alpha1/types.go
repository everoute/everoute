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

package v1alpha1

import (
	// "github.com/everoute/everoute/pkg/types"
	// corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:openapi-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,path=activeprobes

type ActiveProbe struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Active probe spec specifies probe intent for specific active probe request
	Spec ActiveProbeSpec `json:"spec"`
	// Active probe status store collected telemetry info into it
	Status ActiveProbeStatus `json:"status,omitempty"`
}

type ActiveProbeSpec struct {
	Source      Source      `json:"source,omitempty"`
	Destination Destination `json:"destination,omitempty"`
	Packet      Packet      `json:"packet"`
	ProbeTimes  uint32      `json:"probeTimes"`
}

type ActiveProbeStatus struct {
	State           ActiveProbeState           `json:"state"`
	Reason          string                     `json:"reason,omitempty"`
	StartTime       *metav1.Time               `json:"startTime,omitempty"`
	SrcSucceedTimes uint32                     `json:"succeedTimes,omitempty"`
	DstSucceedTimes uint32                     `json:"succeedTimes,omitempty"`
	Tag             uint8                      `json:"tag"`
	Results         map[string]AgenProbeRecord `json:"results,omitempty"` // []map[string]*AgentProbeResult
	CapturedPacket  *Packet                    `json:"capturedPacket,omitempty"`
}

type AgenProbeRecord []*AgentProbeResult

type AgentProbeResult struct {
	AgentNameTemp   string                  `json:"AgentNameTemp,omitempty"`
	NumberOfTimes   uint32                  `json:"numberoftimes,omitempty"`
	AgentProbeState ActiveProbeState        `json:"agentprobestate,omitempty"`
	AgentProbePath  []ActiveProbeTracePoint `json:"agentprobepath,omitempty"`
}

type ActiveProbeTracePoint struct {
	TracePoint TelemetryTracePoint `json:"tracepoint,omitempty"`
	Action     ActiveProbeAction   `json:"action,omitempty"`
}

type ActiveProbeState string

const (
	ActiveProbeReady       ActiveProbeState = "ready"
	ActiveProbeRunning     ActiveProbeState = "running"
	ActiveProbeSendFinshed ActiveProbeState = "sendFinished"
	ActiveProbeCompleted   ActiveProbeState = "completed"
	ActiveProbeFailed      ActiveProbeState = "failed"
	ActiveProbeUnknown     ActiveProbeState = "unknown"
)

type TelemetryTracePoint string

const (
	SecurityPolicyIngress  TelemetryTracePoint = "securitypolicyingress"
	SecurityPolicyEgress   TelemetryTracePoint = "securitypolicyegress"
	IsolationPolicyIngress TelemetryTracePoint = "isolationpolicyingress"
	IsolationPolicyEgress  TelemetryTracePoint = "isolationpolicyegress"
	ForensicPolicyIngress  TelemetryTracePoint = "forensicpolicyingress"
	FroensicPolicyEgress   TelemetryTracePoint = "forensicpolicyegress"

	LocalFrowarding TelemetryTracePoint = "localforwarding"
	ClsForwarding   TelemetryTracePoint = "clsforwarding"
)

type ActiveProbeAction string

const (
	ActiveProbeDrop    ActiveProbeAction = "drop"
	ActiveProbeAllow   ActiveProbeAction = "allow"
	ActiveProbeForward ActiveProbeAction = "forward"
	// other action
)

type Source struct {
	Endpoint   string `json:"endpoint,omitempty"`
	NameSpace  string `json:"namespace,omitempty"`
	IP         string `json:"ip,omitempty"`
	MAC        string `json:"mac,omitempty"`
	AgentName  string `json:"agentname,omitempty"`
	BridgeName string `json:"bridgename,omitempty"`
	Ofport     int32  `json:"ofport,omitempty"`
}

type Destination struct {
	Endpoint   string `json:"endpoint,omitempty"`
	NameSpace  string `json:"namespace,omitempty"`
	IP         string `json:"ip,omitempty"`
	MAC        string `json:"mac,omitempty"`
	AgentName  string `json:"agentname,omitempty"`
	BridgeName string `json:"bridgename,omitempty"`
	Ofport     int32  `json:"ofport,omitempty"`
	Service    string `json:"service,omitempty"`
}

type IPHeader struct {
	Protocol uint32 `json:"protocol,omitempty"`
	TTL      uint32 `json:"ttl,omitempty"`
	Flags    uint32 `json:"flags,omitempty"`
	DSCP     uint32 `json:"dscp,omitempty"`
}

type TransportHeader struct {
	ICMP *ICMPEchoRequestHeader `json:"icmp,omitempty"`
	TCP  *TCPHeader             `json:"tcp,omitempty"`
	UDP  *UDPHeader             `json:"udp,omitempty"`
}

type ICMPEchoRequestHeader struct {
	ID       uint32 `json:"id,omitempty"`
	Sequence uint32 `json:"sequence,omitempty"`
}

type UDPHeader struct {
	SrcPort uint32 `json:"srcport,omitempty"`
	DstPort uint32 `json:"dstport,omitempty"`
}

type TCPHeader struct {
	SrcPort uint32 `json:"srcport,omitempty"`
	DstPort uint32 `json:"dstport,omitempty"`
	Flags   uint32 `json:"flags,omitempty"`
}

// Packet includes header info.
type Packet struct {
	SrcIP string `json:"srcip,omitempty"`
	DstIP string `json:"dstip,omitempty"`
	// Length is the IP packet length (include the IPv4 header length).
	Length          uint16          `json:"headerlength,omitempty"`
	IPHeader        IPHeader        `json:"ipheader,omitempty"`
	TransportHeader TransportHeader `json:"transportHeader,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ActiveProbeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ActiveProbe `json:"items"`
}
