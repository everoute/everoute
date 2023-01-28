package cache

import (
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/ofnet/ofctrl"
)

type LBFlowEntry struct {
	LBIP     string
	PortName string
	Flow     *ofctrl.Flow
}

type SvcOvsInfo struct {
	lock sync.RWMutex
	// svcID is svcNs/svcName
	svcID string
	// groupMap key is portName, value is groupID
	groupMap map[string]*ofctrl.Group
	// lbMap the first key is lbIP, the second key is portName, value is flowID in NatBrServiceLBTable
	lbMap map[string]map[string]*ofctrl.Flow
	// sessionAffinityMap key is lbIP, value is flowID list in NatBrSessionAffinityLearnTable
	sessionAffinityMap map[string][]*ofctrl.Flow
}

func NewSvcOvsInfo(svcID string) *SvcOvsInfo {
	return &SvcOvsInfo{
		svcID:              svcID,
		groupMap:           make(map[string]*ofctrl.Group),
		lbMap:              make(map[string]map[string]*ofctrl.Flow),
		sessionAffinityMap: make(map[string][]*ofctrl.Flow),
	}
}

func (s *SvcOvsInfo) GetGroup(portName string) *ofctrl.Group {
	s.lock.RLock()
	defer s.lock.RUnlock()

	return s.groupMap[portName]
}

func (s *SvcOvsInfo) SetGroup(portName string, group *ofctrl.Group) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.groupMap[portName] = group
	log.Debugf("Set the port name %s corresponding group id to %d", portName, group.GroupID)
}

func (s *SvcOvsInfo) DeleteGroup(portName string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	delete(s.groupMap, portName)
	log.Debugf("Delete the group id of port name %s", portName)
}

func (s *SvcOvsInfo) GetLBFlowIDsByIP(lbIP string) []*ofctrl.Flow {
	s.lock.RLock()
	defer s.lock.RUnlock()

	flows := make([]*ofctrl.Flow, 0)
	flowMap := s.lbMap[lbIP]
	if flowMap == nil {
		return flows
	}

	for _, v := range flowMap {
		flows = append(flows, v)
	}
	return flows
}

func (s *SvcOvsInfo) GetLBFlowIDsByPortName(portName string) []*ofctrl.Flow {
	s.lock.RLock()
	defer s.lock.RUnlock()

	flows := make([]*ofctrl.Flow, 0)
	for _, v := range s.lbMap {
		if v == nil {
			continue
		}
		for p, f := range v {
			if p == portName {
				flows = append(flows, f)
			}
		}
	}
	return flows
}

func (s *SvcOvsInfo) SetLBMap(lbFlows []LBFlowEntry) {
	s.lock.Lock()
	defer s.lock.Unlock()

	for i := range lbFlows {
		portFlowMap := s.lbMap[lbFlows[i].LBIP]
		if portFlowMap == nil {
			portFlowMap = make(map[string]*ofctrl.Flow)
		}
		portFlowMap[lbFlows[i].PortName] = lbFlows[i].Flow
		s.lbMap[lbFlows[i].LBIP] = portFlowMap
	}
}

func (s *SvcOvsInfo) DeleteLBFlowsByIP(lbIP string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	delete(s.lbMap, lbIP)
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

func (s *SvcOvsInfo) GetSessionAffinityFlows(lbIP string) []*ofctrl.Flow {
	s.lock.RLock()
	defer s.lock.RUnlock()

	return s.sessionAffinityMap[lbIP]
}

func (s *SvcOvsInfo) DeleteSessionAffinityFlows(lbIP string) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	delete(s.sessionAffinityMap, lbIP)
}
