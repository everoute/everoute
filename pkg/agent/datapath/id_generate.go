package datapath

import (
	"errors"
	"sync"

	"github.com/contiv/libOpenflow/openflow13"
	"github.com/contiv/ofnet/ofctrl/cookie"
	log "github.com/sirupsen/logrus"
)

const InvalidGroupID uint32 = 0

type idGenerate struct {
	lock     sync.RWMutex
	idUint32 uint32
	idUint64 uint64
}

func (i *idGenerate) ascendUint32() {
	i.lock.Lock()
	defer i.lock.Unlock()

	i.idUint32++
}

func (i *idGenerate) ascendUint64() {
	i.lock.Lock()
	defer i.lock.Unlock()

	i.idUint64++
}

var learnCookieID = &idGenerate{}
var groupID = &idGenerate{}

func getLearnCookieID() (uint64, error) {
	learnCookieID.ascendUint64()
	if learnCookieID.idUint64 >= (uint64(1) << cookie.BitWidthFlowId) {
		log.Error("No enough avalible cookie id")
		return 0, errors.New("no enough avalible cookie id")
	}
	return learnCookieID.idUint64, nil
}

func getGroupID() (uint32, error) {
	groupID.ascendUint32()
	if groupID.idUint32 > openflow13.OFPG_MAX {
		log.Error("No enough avalible group id")
		return InvalidGroupID, errors.New("no enough avalible group id")
	}

	return groupID.idUint32, nil
}
