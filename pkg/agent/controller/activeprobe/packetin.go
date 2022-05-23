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
	"fmt"
	"github.com/contiv/libOpenflow/protocol"
	"github.com/contiv/ofnet/ofctrl"
	"github.com/everoute/everoute/pkg/agent/datapath"
	activeprobev1alph1 "github.com/everoute/everoute/pkg/apis/activeprobe/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog"
)

func (a *ActiveprobeController) HandlePacketIn(packetIn *ofctrl.PacketIn) error {
	// In contoller runtime frame work, it's not easy to register packetIn callback in activeprobe controller
	// but we need active probe controller process packetIn for telemetry result parsing.
	// FIXME if runnable callback register func is not work, we need another module to parsing telemetry result
	// and sync it to apiserver: update activeprobe status

	// Parsing packetIn generate activeProbe status

	ap := activeprobev1alph1.ActiveProbe{}
	reason := ""

	state, tag, apResult, err := a.parsePacketIn(packetIn)
	if err != nil {
		klog.Errorf("parsePacketIn error: %+v", err)
		return err
	}
	fmt.Println("state = ", state)
	fmt.Println("tag = ", tag)
	fmt.Println("apResult = ", apResult)
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		name := a.RunningActiveprobe[tag]
		namespacedName := types.NamespacedName{
			Namespace: "",
			Name:      name,
		}
		if err := a.K8sClient.Get(context.TODO(), namespacedName, &ap); err != nil {
			klog.Warningf("Update ActiveProbe failed: %+v", err)
		}
		err = a.updateActiveProbeStatus(&ap, state, apResult, reason, tag)
		if err != nil {
			klog.Warningf("Update ActiveProbe failed: %+v", err)
			return err
		}
		return nil
	})
	if err != nil {
		klog.Errorf("Update ActiveProbe error: %+v", err)
	}

	return nil
}

func (a *ActiveprobeController) parsePacketIn(packetIn *ofctrl.PacketIn) (activeprobev1alph1.ActiveProbeState, uint8, *activeprobev1alph1.AgentProbeResult, error) {
	var err error
	var tag uint8
	//var ctNwDst, ctNwSrc, ipDst, ipSrc string
	var reg4Val, reg5Val uint32
	var inPort uint32
	state := activeprobev1alph1.ActiveProbeFailed
	var telemetryTracePoint activeprobev1alph1.TelemetryTracePoint
	var activeProbeAction activeprobev1alph1.ActiveProbeAction
	//status := &activeprobev1alph1.ActiveProbeStatus{}
	agentProbeResult := activeprobev1alph1.AgentProbeResult{}
	activeProbeTracePoint := activeprobev1alph1.ActiveProbeTracePoint{}
	matchers := packetIn.GetMatches()
	if packetIn.Data.Ethertype == protocol.IPv4_MSG {
		ipPacket, ok := packetIn.Data.Data.(*protocol.IPv4)
		if !ok {
			state = activeprobev1alph1.ActiveProbeFailed
			return state, 0, nil, errors.New("invalid IPv4 packet")
		}
		//state = activeprobev1alph1.ActiveProbeCompleted
		tag = ipPacket.DSCP
		println("tag: ", tag)

		if match := getMatchInPortField(matchers); match != nil {
			inPort, err = getInportVal(match)
			if err != nil {
				return state, tag, nil, err
			}
		}

		flowActionField := ofctrl.NewRegField(4, 0, 15, "flowAction")
		activeProbeField := ofctrl.NewRegField(5, 0, 8, "activeProbe")

		reg4Val, err = getRegValue(matchers, flowActionField)
		if err != nil {
			return state, tag, nil, err
		}
		if reg4Val == datapath.PolicyRuleActionAllow {
			activeProbeAction = activeprobev1alph1.ActiveProbeAllow
		} else if reg4Val == datapath.PolicyRuleActionDeny {
			activeProbeAction = activeprobev1alph1.ActiveProbeDrop
		}

		reg5Val, err = getRegValue(matchers, activeProbeField)
		if err != nil {
			return state, tag, nil, err
		}
		if reg5Val == datapath.Tier1PolicyMatch && inPort == datapath.POLICY_TO_LOCAL_PORT {
			telemetryTracePoint = activeprobev1alph1.IsolationPolicyEgress
		} else if reg5Val == datapath.Tier2PolicyMatch && inPort == datapath.POLICY_TO_LOCAL_PORT {
			telemetryTracePoint = activeprobev1alph1.FroensicPolicyEgress
		} else if reg5Val == datapath.Tier3PolicyMatch && inPort == datapath.POLICY_TO_LOCAL_PORT {
			telemetryTracePoint = activeprobev1alph1.SecurityPolicyEgress
		} else if reg5Val == datapath.Tier1PolicyMatch && inPort == datapath.POLICY_TO_CLS_PORT {
			telemetryTracePoint = activeprobev1alph1.IsolationPolicyIngress
		} else if reg5Val == datapath.Tier2PolicyMatch && inPort == datapath.POLICY_TO_CLS_PORT {
			telemetryTracePoint = activeprobev1alph1.ForensicPolicyIngress
		} else if reg5Val == datapath.Tier3PolicyMatch && inPort == datapath.POLICY_TO_CLS_PORT {
			telemetryTracePoint = activeprobev1alph1.SecurityPolicyIngress
		}

		activeProbeTracePoint.TracePoint = telemetryTracePoint
		activeProbeTracePoint.Action = activeProbeAction

		agentProbeResult.AgentProbePath = append(agentProbeResult.AgentProbePath, activeProbeTracePoint)
		//status.Results = append(status.Results, agentProbeResult)
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
