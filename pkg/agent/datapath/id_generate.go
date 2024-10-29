package datapath

import (
	"errors"
	"sync"

	"github.com/contiv/ofnet/ofctrl/cookie"
	klog "k8s.io/klog/v2"
)

const InvalidGroupID uint32 = 0

//nolint:all
type idGenerate struct {
	lock     sync.RWMutex
	idUint32 uint32
	idUint64 uint64
}

//nolint:all
func (i *idGenerate) ascendUint32() uint32 {
	i.lock.Lock()
	defer i.lock.Unlock()

	i.idUint32++
	return i.idUint32
}

func (i *idGenerate) ascendUint64() uint64 {
	i.lock.Lock()
	defer i.lock.Unlock()

	i.idUint64++
	return i.idUint64
}

var learnCookieID = &idGenerate{}

func getLearnCookieID() (uint64, error) {
	id := learnCookieID.ascendUint64()
	if id >= (uint64(1) << cookie.BitWidthFlowId) {
		klog.Error("No enough avalible cookie id")
		return 0, errors.New("no enough avalible cookie id")
	}
	return id, nil
}
