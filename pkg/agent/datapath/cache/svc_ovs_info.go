package cache

import (
	"sync"

	"github.com/contiv/ofnet/ofctrl"

	ertype "github.com/everoute/everoute/pkg/types"
)

type CreateGroupFunc func() (*ofctrl.Group, error)

type SvcFlowEntry struct {
	LBIP     string
	PortName string
	Flow     *ofctrl.Flow
}

type SvcGroupEntry struct {
	PortName      string
	TrafficPolicy ertype.TrafficPolicyType
	Group         *ofctrl.Group
}

type SvcOvsInfo struct {
	lock sync.RWMutex
	// svcID is svcNs/svcName
	svcID string
	// groupMap first key is portName, second key is local/cluster, value is group
	groupMap map[string]map[ertype.TrafficPolicyType]*ofctrl.Group
	// lbMap the first key is clusterIP/lbIP/"", the second key is portName, value is flow in NatBrServiceLBTable
	lbMap map[string]map[string]*ofctrl.Flow
	// sessionAffinityMap the first key is clusterIP/lbIP/"", the second key is portName, value is flow in NatBrSessionAffinityLearnTable
	sessionAffinityMap map[string]map[string]*ofctrl.Flow
}

func NewSvcOvsInfo(svcID string) *SvcOvsInfo {
	return &SvcOvsInfo{
		svcID:              svcID,
		groupMap:           make(map[string]map[ertype.TrafficPolicyType]*ofctrl.Group),
		lbMap:              make(map[string]map[string]*ofctrl.Flow),
		sessionAffinityMap: make(map[string]map[string]*ofctrl.Flow),
	}
}

func (s *SvcOvsInfo) GetGroup(portName string, groupType ertype.TrafficPolicyType) *ofctrl.Group {
	s.lock.RLock()
	defer s.lock.RUnlock()

	if s.groupMap[portName] != nil {
		return s.groupMap[portName][groupType]
	}

	return nil
}

func (s *SvcOvsInfo) GetGroupAndCreateIfEmpty(portName string, groupType ertype.TrafficPolicyType, f CreateGroupFunc) (*ofctrl.Group, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.groupMap[portName] != nil {
		if s.groupMap[portName][groupType] != nil {
			return s.groupMap[portName][groupType], nil
		}
	} else {
		s.groupMap[portName] = make(map[ertype.TrafficPolicyType]*ofctrl.Group)
	}

	gp, err := f()
	if err != nil {
		return nil, err
	}
	s.groupMap[portName][groupType] = gp

	return gp, nil
}

func (s *SvcOvsInfo) GetAllGroups() []SvcGroupEntry {
	s.lock.RLock()
	defer s.lock.RUnlock()

	var res []SvcGroupEntry
	for p := range s.groupMap {
		if s.groupMap[p] != nil {
			for k := range s.groupMap[p] {
				if s.groupMap[p][k] != nil {
					res = append(res, SvcGroupEntry{PortName: p, TrafficPolicy: k, Group: s.groupMap[p][k]})
				}
			}
		}
	}
	return res
}

func (s *SvcOvsInfo) DeleteAllGroup() {
	s.lock.Lock()
	defer s.lock.Unlock()

	for p := range s.groupMap {
		if s.groupMap[p] != nil {
			for k := range s.groupMap[p] {
				if s.groupMap[p][k] != nil {
					s.groupMap[p][k].Delete()
				}
			}
		}
	}
	s.groupMap = make(map[string]map[ertype.TrafficPolicyType]*ofctrl.Group)
}

func (s *SvcOvsInfo) DeleteGroupIfExist(portName string, groupType ertype.TrafficPolicyType) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.groupMap[portName] == nil {
		return
	}

	if s.groupMap[portName][groupType] == nil {
		return
	}

	s.groupMap[portName][groupType].Delete()
	delete(s.groupMap[portName], groupType)
	if len(s.groupMap[portName]) == 0 {
		delete(s.groupMap, portName)
	}
}

func (s *SvcOvsInfo) GetLBFlow(lbIP, portName string) *ofctrl.Flow {
	s.lock.RLock()
	defer s.lock.RUnlock()
	flowMap := s.lbMap[lbIP]
	if flowMap == nil {
		return nil
	}
	return flowMap[portName]
}

func (s *SvcOvsInfo) GetLBFlowsByIP(lbIP string) []SvcFlowEntry {
	s.lock.RLock()
	defer s.lock.RUnlock()

	var res []SvcFlowEntry
	flowMap := s.lbMap[lbIP]
	if flowMap == nil {
		return res
	}

	for portName, flow := range flowMap {
		if flow != nil {
			res = append(res, SvcFlowEntry{LBIP: lbIP, PortName: portName, Flow: flow})
		}
	}
	return res
}

func (s *SvcOvsInfo) GetLBFlowsByPortName(portName string) []SvcFlowEntry {
	s.lock.RLock()
	defer s.lock.RUnlock()

	var res []SvcFlowEntry
	for ip, v := range s.lbMap {
		if v == nil {
			continue
		}
		for p, f := range v {
			if p == portName && f != nil {
				res = append(res, SvcFlowEntry{LBIP: ip, PortName: p, Flow: f})
			}
		}
	}
	return res
}

func (s *SvcOvsInfo) GetAllLBFlows() []SvcFlowEntry {
	s.lock.RLock()
	defer s.lock.RUnlock()

	var res []SvcFlowEntry
	for ip := range s.lbMap {
		for p, f := range s.lbMap[ip] {
			if f != nil {
				res = append(res, SvcFlowEntry{LBIP: ip, PortName: p, Flow: f})
			}
		}
	}
	return res
}

func (s *SvcOvsInfo) SetLBFlow(lbIP, portName string, flow *ofctrl.Flow) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if flow == nil {
		if s.lbMap[lbIP] != nil {
			delete(s.lbMap[lbIP], portName)
		}
		return
	}

	if s.lbMap[lbIP] == nil {
		s.lbMap[lbIP] = make(map[string]*ofctrl.Flow)
	}
	s.lbMap[lbIP][portName] = flow
}

func (s *SvcOvsInfo) DeleteLBFlowsByPortName(portName string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	for _, v := range s.lbMap {
		if v == nil {
			continue
		}
		for p := range v {
			if p == portName {
				delete(v, portName)
			}
		}
	}
}

func (s *SvcOvsInfo) GetSessionAffinityFlowsByIP(lbIP string) []SvcFlowEntry {
	s.lock.RLock()
	defer s.lock.RUnlock()

	var res []SvcFlowEntry
	if s.sessionAffinityMap[lbIP] == nil {
		return res
	}

	for p, f := range s.sessionAffinityMap[lbIP] {
		if f != nil {
			res = append(res, SvcFlowEntry{LBIP: lbIP, PortName: p, Flow: f})
		}
	}

	return res
}

func (s *SvcOvsInfo) GetSessionAffinityFlowsByPortName(portName string) []SvcFlowEntry {
	s.lock.RLock()
	defer s.lock.RUnlock()

	var res []SvcFlowEntry
	for ip, v := range s.sessionAffinityMap {
		for p, f := range v {
			if p != portName || f == nil {
				continue
			}
			res = append(res, SvcFlowEntry{LBIP: ip, PortName: portName, Flow: f})
		}
	}
	return res
}

func (s *SvcOvsInfo) GetAllSessionAffinityFlows() []SvcFlowEntry {
	s.lock.RLock()
	defer s.lock.RUnlock()

	var res []SvcFlowEntry
	for ip, v := range s.sessionAffinityMap {
		for p, f := range v {
			if f != nil {
				res = append(res, SvcFlowEntry{LBIP: ip, PortName: p, Flow: f})
			}
		}
	}
	return res
}

func (s *SvcOvsInfo) GetSessionAffinityFlow(lbIP, portName string) *ofctrl.Flow {
	s.lock.RLock()
	defer s.lock.RUnlock()

	if s.sessionAffinityMap[lbIP] == nil {
		return nil
	}

	return s.sessionAffinityMap[lbIP][portName]
}

func (s *SvcOvsInfo) SetSessionAffinityFlow(lbIP, portName string, flow *ofctrl.Flow) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if flow == nil {
		if s.sessionAffinityMap[lbIP] != nil {
			delete(s.sessionAffinityMap[lbIP], portName)
		}
		return
	}

	if s.sessionAffinityMap[lbIP] == nil {
		s.sessionAffinityMap[lbIP] = make(map[string]*ofctrl.Flow)
	}
	s.sessionAffinityMap[lbIP][portName] = flow
}
