package datapath

import (
	"errors"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/contiv/ofnet/ofctrl/cookie"
)

//nolint
type idGenerate struct {
	lock     sync.RWMutex
	idUint32 uint32
	idUint64 uint64
}

//nolint
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

func getLearnCookieID() (uint64, error) {
	learnCookieID.ascendUint64()
	if learnCookieID.idUint64 >= (uint64(1) << cookie.BitWidthFlowId) {
		log.Error("no enough avalible cookie id")
		return 0, errors.New("no enough avalible cookie id")
	}
	return learnCookieID.idUint64, nil
}
