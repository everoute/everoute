package datapath

import (
	"errors"
	"sync"

	"github.com/contiv/ofnet/ofctrl/cookie"
	"github.com/everoute/everoute/pkg/constants"
	log "github.com/sirupsen/logrus"
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
		log.Error("No enough avalible cookie id")
		return 0, errors.New("no enough avalible cookie id")
	}
	return id, nil
}

type GroupIDAllocator struct {
	lock    sync.Mutex
	iter    uint32
	offset  uint32
	release []uint32
}

func NewGroupIDAllocate(iter uint32) *GroupIDAllocator {
	if iter > constants.MaxGroupIter {
		return nil
	}
	return &GroupIDAllocator{
		iter:    iter,
		release: make([]uint32, 0),
	}
}

func (g *GroupIDAllocator) Allocate() uint32 {
	g.lock.Lock()
	defer g.lock.Unlock()

	if len(g.release) > 0 {
		gID := g.release[0]
		g.release = g.release[1:]
		return gID
	}

	if g.offset+1 < 1<<(32-constants.BitWidthGroupIter) {
		g.offset += 1
		return g.iter<<(32-constants.BitWidthGroupIter) + g.offset
	}

	return InvalidGroupID
}

func (g *GroupIDAllocator) Release(gID uint32) {
	g.lock.Lock()
	defer g.lock.Unlock()
	g.release = append(g.release, gID)
}

func (g *GroupIDAllocator) Max() uint32 {
	maxOffset := 1<<(32-constants.BitWidthGroupIter) - 1
	return g.iter<<(32-constants.BitWidthGroupIter) + uint32(maxOffset)
}

func (g *GroupIDAllocator) GetIter() uint32 {
	return g.iter
}
