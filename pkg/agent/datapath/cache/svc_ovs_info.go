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
	// groupMap key is portName, value is group
	groupMap map[string]*ofctrl.Group
	// lbMap the first key is lbIP, the second key is portName, value is flow in NatBrServiceLBTable
	lbMap map[string]map[string]*ofctrl.Flow
	// sessionAffinityMap key is lbIP, value is flow list in NatBrSessionAffinityLearnTable
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

func (s *SvcOvsInfo) GetLBFlow(lbIP, portName string) *ofctrl.Flow {
	s.lock.RLock()
	defer s.lock.RUnlock()
	flowMap := s.lbMap[lbIP]
	if flowMap == nil {
		return nil
	}
	return flowMap[portName]
}

func (s *SvcOvsInfo) DelLBFlow(lbIP, portName string) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	flowMap := s.lbMap[lbIP]
	if flowMap == nil {
		delete(s.lbMap, lbIP)
		return
	}
	delete(flowMap, portName)

	if len(flowMap) == 0 {
		delete(s.lbMap, lbIP)
	}
	return
}

func (s *SvcOvsInfo) GetLBFlowsByIP(lbIP string) []LBFlowEntry {
	s.lock.RLock()
	defer s.lock.RUnlock()

	var res []LBFlowEntry
	flowMap := s.lbMap[lbIP]
	if flowMap == nil {
		return res
	}

	for portName, flow := range flowMap {
		res = append(res, LBFlowEntry{LBIP: lbIP, PortName: portName, Flow: flow})
	}
	return res
}

func (s *SvcOvsInfo) GetLBFlowsByPortName(portName string) []LBFlowEntry {
	s.lock.RLock()
	defer s.lock.RUnlock()

	var res []LBFlowEntry
	for ip, v := range s.lbMap {
		if v == nil {
			continue
		}
		for p, f := range v {
			if p == portName {
				res = append(res, LBFlowEntry{LBIP: ip, PortName: p, Flow: f})
			}
		}
	}
	return res
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

	ips := make([]string, 0)
	for ip, v := range s.lbMap {
		ips = append(ips, ip)
		if v == nil {
			continue
		}
		for p := range v {
			if p == portName {
				delete(v, portName)
			}
		}
	}

	for _, ip := range ips {
		if s.lbMap[ip] == nil || len(s.lbMap) == 0 {
			delete(s.lbMap, ip)
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
