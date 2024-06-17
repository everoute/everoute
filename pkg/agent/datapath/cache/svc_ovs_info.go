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
	FlowID   uint64
}

type SvcGroupEntry struct {
	PortName      string
	TrafficPolicy ertype.TrafficPolicyType
	GroupID       uint32
}

type SvcOvsInfo struct {
	lock sync.RWMutex
	// svcID is svcNs/svcName
	svcID string
	// groupMap first key is portName, second key is local/cluster, value is group
	groupMap map[string]map[ertype.TrafficPolicyType]uint32
	// lbMap the first key is clusterIP/lbIP/"", the second key is portName, value is flow in NatBrServiceLBTable
	lbMap map[string]map[string]uint64
	// sessionAffinityMap the first key is clusterIP/lbIP/"", the second key is portName, value is flow in NatBrSessionAffinityLearnTable
	sessionAffinityMap map[string]map[string]uint64
}

func NewSvcOvsInfo(svcID string) *SvcOvsInfo {
	return &SvcOvsInfo{
		svcID:              svcID,
		groupMap:           make(map[string]map[ertype.TrafficPolicyType]uint32),
		lbMap:              make(map[string]map[string]uint64),
		sessionAffinityMap: make(map[string]map[string]uint64),
	}
}

func (s *SvcOvsInfo) GetGroup(portName string, groupType ertype.TrafficPolicyType) uint32 {
	s.lock.RLock()
	defer s.lock.RUnlock()

	if s.groupMap[portName] != nil {
		return s.groupMap[portName][groupType]
	}

	return UnexistGroupID
}

func (s *SvcOvsInfo) GetGroupAndCreateIfEmpty(portName string, groupType ertype.TrafficPolicyType, f CreateGroupFunc) (uint32, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.groupMap[portName] != nil {
		if s.groupMap[portName][groupType] != UnexistGroupID {
			return s.groupMap[portName][groupType], nil
		}
	} else {
		s.groupMap[portName] = make(map[ertype.TrafficPolicyType]uint32)
	}

	gp, err := f()
	if err != nil {
		return UnexistGroupID, err
	}
	s.groupMap[portName][groupType] = gp.GroupID

	return gp.GroupID, nil
}

func (s *SvcOvsInfo) GetAllGroups() []SvcGroupEntry {
	s.lock.RLock()
	defer s.lock.RUnlock()

	var res []SvcGroupEntry
	for p := range s.groupMap {
		if s.groupMap[p] != nil {
			for k := range s.groupMap[p] {
				if s.groupMap[p][k] != UnexistGroupID {
					res = append(res, SvcGroupEntry{PortName: p, TrafficPolicy: k, GroupID: s.groupMap[p][k]})
				}
			}
		}
	}
	return res
}

func (s *SvcOvsInfo) DeleteGroupIfExist(sw *ofctrl.OFSwitch, portName string, groupType ertype.TrafficPolicyType) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.groupMap[portName] == nil {
		return
	}

	if gpID, ok := s.groupMap[portName][groupType]; !ok {
		return
	} else if gpID == UnexistGroupID {
		delete(s.groupMap[portName], groupType)
		return
	}

	_ = ofctrl.DeleteGroup(sw, s.groupMap[portName][groupType])
	delete(s.groupMap[portName], groupType)
	if len(s.groupMap[portName]) == 0 {
		delete(s.groupMap, portName)
	}
}

func (s *SvcOvsInfo) GetLBFlow(lbIP, portName string) uint64 {
	s.lock.RLock()
	defer s.lock.RUnlock()
	flowMap := s.lbMap[lbIP]
	if flowMap == nil {
		return UnexistFlowID
	}
	return flowMap[portName]
}

func (s *SvcOvsInfo) GetAllLBFlows() []SvcFlowEntry {
	s.lock.RLock()
	defer s.lock.RUnlock()

	var res []SvcFlowEntry
	for ip := range s.lbMap {
		for p, f := range s.lbMap[ip] {
			if f != UnexistFlowID {
				res = append(res, SvcFlowEntry{LBIP: ip, PortName: p, FlowID: f})
			}
		}
	}
	return res
}

func (s *SvcOvsInfo) SetLBFlow(lbIP, portName string, flowID uint64) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if flowID == UnexistFlowID {
		if s.lbMap[lbIP] != nil {
			delete(s.lbMap[lbIP], portName)
		}
		if len(s.lbMap[lbIP]) == 0 {
			delete(s.lbMap, lbIP)
		}
		return
	}

	if s.lbMap[lbIP] == nil {
		s.lbMap[lbIP] = make(map[string]uint64)
	}
	s.lbMap[lbIP][portName] = flowID
}

func (s *SvcOvsInfo) DeleteLBFlowsByPortName(portName string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	delIPs := []string{}
	for k, v := range s.lbMap {
		if len(v) == 0 {
			delIPs = append(delIPs, k)
			continue
		}
		for p := range v {
			if p == portName {
				delete(v, portName)
			}
		}
		if len(v) == 0 {
			delIPs = append(delIPs, k)
		}
	}

	for _, ip := range delIPs {
		delete(s.lbMap, ip)
	}
}

func (s *SvcOvsInfo) GetAllSessionAffinityFlows() []SvcFlowEntry {
	s.lock.RLock()
	defer s.lock.RUnlock()

	var res []SvcFlowEntry
	for ip, v := range s.sessionAffinityMap {
		for p, f := range v {
			if f != UnexistFlowID {
				res = append(res, SvcFlowEntry{LBIP: ip, PortName: p, FlowID: f})
			}
		}
	}
	return res
}

func (s *SvcOvsInfo) GetSessionAffinityFlow(lbIP, portName string) uint64 {
	s.lock.RLock()
	defer s.lock.RUnlock()

	if s.sessionAffinityMap[lbIP] == nil {
		return UnexistFlowID
	}

	return s.sessionAffinityMap[lbIP][portName]
}

func (s *SvcOvsInfo) SetSessionAffinityFlow(lbIP, portName string, flowID uint64) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if flowID == UnexistFlowID {
		if s.sessionAffinityMap[lbIP] != nil {
			delete(s.sessionAffinityMap[lbIP], portName)
		}
		if len(s.sessionAffinityMap[lbIP]) == 0 {
			delete(s.sessionAffinityMap, lbIP)
		}
		return
	}

	if s.sessionAffinityMap[lbIP] == nil {
		s.sessionAffinityMap[lbIP] = make(map[string]uint64)
	}
	s.sessionAffinityMap[lbIP][portName] = flowID
}

func (s *SvcOvsInfo) IsEmpty() bool {
	s.lock.RLock()
	defer s.lock.RUnlock()

	if len(s.groupMap) > 0 {
		return false
	}

	if len(s.lbMap) > 0 {
		return false
	}

	if len(s.sessionAffinityMap) > 0 {
		return false
	}
	return true
}
