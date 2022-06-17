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

package activeprobe

import (
	"context"
	"errors"

	"github.com/contiv/libOpenflow/protocol"
	"github.com/contiv/ofnet/ofctrl"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog"

	"github.com/everoute/everoute/pkg/agent/datapath"
	activeprobev1alph1 "github.com/everoute/everoute/pkg/apis/activeprobe/v1alpha1"
)

const (
	FlowAction                     = "flowAction"
	FlowActionRegID         int    = 4
	FlowActionRegLeftIndex  uint32 = 0
	FlowActionRegRigthInnex uint32 = 15

	ActiveProbe                     = "activeProbe"
	ActiveProbeRegID         int    = 5
	ActiveProbeRegLeftIndex  uint32 = 0
	ActiveProbeRegRigthIndex uint32 = 8
)

func (a *Controller) HandlePacketIn(packetIn *ofctrl.PacketIn) error {
	klog.Infof("start func HandlePacketIn")
	a.RunningActiveprobeMutex.Lock()
	defer a.RunningActiveprobeMutex.Unlock()
	a.PktRcvdCnt++
	ap := activeprobev1alph1.ActiveProbe{}
	reason := ""

	state, tag, apResult, err := a.parsePacketIn(packetIn)

	_, ok := a.RunningActiveprobe[tag]
	if !ok {
		return errors.New("when this packet arrives, it has timed out")
	}

	// Retry when update CRD conflict which caused by multiple agents updating one CRD at same time.
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {

		name := a.RunningActiveprobe[tag].name
		namespacedName := types.NamespacedName{
			Namespace: "",
			Name:      name,
		}
		if err := a.K8sClient.Get(context.TODO(), namespacedName, &ap); err != nil {
			klog.Warningf("Update ActiveProbe failed: %+v", err)
		}

		apResult.NumberOfTimes = a.PktRcvdCnt
		apResult.AgentProbeState = state

		ap.Status.SucceedTimes = a.PktRcvdCnt
		err = a.updateActiveProbeStatus(&ap, apResult, reason)
		if err != nil {
			klog.Warningf("Update ActiveProbe failed: %+v", err)
			return err
		}
		return nil
	})
	if err != nil {
		klog.Errorf("retry Update ActiveProbe failed: %+v", err)
	}
	return err
}

func (a *Controller) parsePacketIn(packetIn *ofctrl.PacketIn) (activeprobev1alph1.ActiveProbeState, uint8, *activeprobev1alph1.AgentProbeResult, error) {
	klog.Infof("start func parsePacketIn")
	var err error
	var tag uint8
	var reg4Val, reg5Val uint32
	var inPort uint32
	state := activeprobev1alph1.ActiveProbeFailed
	var telemetryTracePoint activeprobev1alph1.TelemetryTracePoint
	var activeProbeAction activeprobev1alph1.ActiveProbeAction
	agentProbeResult := activeprobev1alph1.AgentProbeResult{}
	activeProbeTracePoint := activeprobev1alph1.ActiveProbeTracePoint{}
	matchers := packetIn.GetMatches()
	if packetIn.Data.Ethertype == protocol.IPv4_MSG {
		ipPacket, ok := packetIn.Data.Data.(*protocol.IPv4)
		if !ok {
			state = activeprobev1alph1.ActiveProbeFailed
			return state, 0, &agentProbeResult, errors.New("invalid IPv4 packet")
		}
		tag = ipPacket.DSCP

		if match := getMatchInPortField(matchers); match != nil {
			inPort, err = getInportVal(match)
			if err != nil {
				return state, tag, &agentProbeResult, err
			}
		}

		flowActionField := ofctrl.NewRegField(FlowActionRegID, FlowActionRegLeftIndex, FlowActionRegRigthInnex, FlowAction)
		activeProbeField := ofctrl.NewRegField(ActiveProbeRegID, ActiveProbeRegLeftIndex, ActiveProbeRegRigthIndex, ActiveProbe)

		reg4Val, err = getRegValue(matchers, flowActionField)
		if err != nil {
			return state, tag, &agentProbeResult, err
		}
		if reg4Val == datapath.PolicyRuleActionAllow {
			activeProbeAction = activeprobev1alph1.ActiveProbeAllow
		} else if reg4Val == datapath.PolicyRuleActionDeny {
			activeProbeAction = activeprobev1alph1.ActiveProbeDrop
		}

		reg5Val, err = getRegValue(matchers, activeProbeField)
		if err != nil {
			return state, tag, &agentProbeResult, err
		}

		switch {
		case reg5Val == datapath.Tier1PolicyMatch && inPort == datapath.POLICY_TO_LOCAL_PORT:
			telemetryTracePoint = activeprobev1alph1.IsolationPolicyEgress
		case reg5Val == datapath.Tier2PolicyMatch && inPort == datapath.POLICY_TO_LOCAL_PORT:
			telemetryTracePoint = activeprobev1alph1.FroensicPolicyEgress
		case reg5Val == datapath.Tier3PolicyMatch && inPort == datapath.POLICY_TO_LOCAL_PORT:
			telemetryTracePoint = activeprobev1alph1.SecurityPolicyEgress
		case reg5Val == datapath.Tier1PolicyMatch && inPort == datapath.POLICY_TO_CLS_PORT:
			telemetryTracePoint = activeprobev1alph1.IsolationPolicyIngress
		case reg5Val == datapath.Tier2PolicyMatch && inPort == datapath.POLICY_TO_CLS_PORT:
			telemetryTracePoint = activeprobev1alph1.ForensicPolicyIngress
		case reg5Val == datapath.Tier3PolicyMatch && inPort == datapath.POLICY_TO_CLS_PORT:
			telemetryTracePoint = activeprobev1alph1.SecurityPolicyIngress
		}

		activeProbeTracePoint.TracePoint = telemetryTracePoint
		activeProbeTracePoint.Action = activeProbeAction

		agentProbeResult.AgentProbeState = activeprobev1alph1.ActiveProbeCompleted
		agentProbeResult.AgentProbePath = append(agentProbeResult.AgentProbePath, activeProbeTracePoint)
		state = activeprobev1alph1.ActiveProbeCompleted
	}
	return state, tag, &agentProbeResult, nil
}

func getRegValue(matchers *ofctrl.Matchers, field *ofctrl.RegField) (uint32, error) {
	if match := ofctrl.GetMatchRegField(matchers, field); match != nil {
		flowActionVal, err := ofctrl.GetRegValue(match, nil)
		if err != nil {
			return 0, err
		}
		return flowActionVal, nil
	}
	return 0, errors.New("register value cannot be got")
}

func getMatchInPortField(matchers *ofctrl.Matchers) *ofctrl.MatchField {
	return matchers.GetMatchByName("OXM_OF_IN_PORT")
}

func getInportVal(matcher *ofctrl.MatchField) (uint32, error) {
	inPortVal, ok := matcher.GetValue().(uint32)
	if !ok {
		return 0, errors.New("inPort value cannot be got")
	}
	return inPortVal, nil
}
