package cache

import (
	"strconv"
	"sync"

	"github.com/contiv/ofnet/ofctrl"
)

type SvcIndex struct {
	lock sync.RWMutex
	// dnatMap key is ip-port-protocol, value is flowID in NatBrDnatTable
	dnatMap map[string]*ofctrl.Flow
	// svcMap key is svcNs/svcName
	svcMap map[string]*SvcOvsInfo
}

func GenDnatMapKey(ip, protocol string, port int32) string {
	return ip + "-" + strconv.Itoa(int(port)) + "-" + protocol
}

func NewSvcIndex() *SvcIndex {
	return &SvcIndex{
		dnatMap: make(map[string]*ofctrl.Flow),
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

func (s *SvcIndex) TryCleanSvcOvsInfoCache(svcID string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.svcMap[svcID] == nil || s.svcMap[svcID].IsEmpty() {
		delete(s.svcMap, svcID)
	}
}

// used by unittest
func (s *SvcIndex) IsSvcInfoNil(svcID string) bool {
	s.lock.Lock()
	defer s.lock.Unlock()

	return s.svcMap[svcID] == nil
}

func (s *SvcIndex) GetDnatFlow(backend string) *ofctrl.Flow {
	s.lock.RLock()
	defer s.lock.RUnlock()

	return s.dnatMap[backend]
}

func (s *SvcIndex) SetDnatFlow(backend string, flow *ofctrl.Flow) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.dnatMap[backend] = flow
}

func (s *SvcIndex) DeleteDnatFlow(backend string) {
	s.lock.Lock()
	defer s.lock.Unlock()

	delete(s.dnatMap, backend)
}
