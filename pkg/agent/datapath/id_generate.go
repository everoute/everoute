package datapath

import (
	"errors"
	"fmt"
	"sync"

	"github.com/contiv/ofnet/ofctrl/cookie"
	"github.com/kelindar/bitmap"
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

var ErrNumExghaust = fmt.Errorf("no availabel number to allocate")

type NumAllocator struct {
	lock sync.Mutex
	// the bitmap will used end-start/8/1024/1024 MiB cache
	used   bitmap.Bitmap
	start  uint32
	end    uint32
	offset uint32
}

func NewNumAllocator(start, end uint32) (*NumAllocator, error) {
	if start > end {
		return nil, fmt.Errorf("invalid param, start %#x can't bigger than end %#x", start, end)
	}
	return &NumAllocator{
		used:   bitmap.Bitmap{},
		start:  start,
		end:    end,
		offset: 0,
	}, nil
}

func (a *NumAllocator) Allocate() (uint32, error) {
	a.lock.Lock()
	defer a.lock.Unlock()

	oldOffset := a.offset
	for {
		if !a.used.Contains(a.offset) {
			res := a.start + a.offset
			a.used.Set(a.offset)
			a.offset = a.nextOffset(a.offset)
			return res, nil
		}
		a.offset = a.nextOffset(a.offset)
		if a.offset == oldOffset {
			return 0, ErrNumExghaust
		}
	}
}

func (a *NumAllocator) Release(n uint32) {
	a.lock.Lock()
	defer a.lock.Unlock()

	if n < a.start || n > a.end {
		log.Warning("release invalid number")
	}
	a.used.Remove(n - a.start)
}

func (a *NumAllocator) nextOffset(cur uint32) uint32 {
	return (cur + 1) % (a.end + 1 - a.start)
}
