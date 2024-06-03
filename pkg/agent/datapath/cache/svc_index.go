package cache

import (
	"strconv"
	"sync"
)

type SvcIndex struct {
	lock sync.RWMutex
	// dnatMap key is ip-port-protocol, value is flowID in NatBrDnatTable
	dnatMap map[string]uint64
	// svcMap key is svcNs/svcName
	svcMap map[string]*SvcOvsInfo
}

func GenDnatMapKey(ip, protocol string, port int32) string {
	return ip + "-" + strconv.Itoa(int(port)) + "-" + protocol
}

func NewSvcIndex() *SvcIndex {
	return &SvcIndex{
		dnatMap: make(map[string]uint64),
		svcMap:  make(map[string]*SvcOvsInfo),
	}
}

func (s *SvcIndex) GetSvcOvsInfo(svcID string) *SvcOvsInfo {
	s.lock.RLock()
	defer s.lock.RUnlock()

	return s.svcMap[svcID]
}

func (s *SvcIndex) GetSvcOvsInfoAndInitIfEmpty(svcID string) *SvcOvsInfo {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.svcMap[svcID] == nil {
		s.svcMap[svcID] = NewSvcOvsInfo(svcID)
	}

	return s.svcMap[svcID]
}

func (s *SvcIndex) DeleteSvcOvsInfo(svcID string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	delete(s.svcMap, svcID)
}

func (s *SvcIndex) GetDnatFlow(backend string) uint64 {
	s.lock.RLock()
	defer s.lock.RUnlock()

	return s.dnatMap[backend]
}

func (s *SvcIndex) SetDnatFlow(backend string, flowID uint64) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.dnatMap[backend] = flowID
}

func (s *SvcIndex) DeleteDnatFlow(backend string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	delete(s.dnatMap, backend)
}
