package datapath

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/contiv/ofnet/ofctrl/cookie"
	"github.com/kelindar/bitmap"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/everoute/everoute/pkg/constants"
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

var ErrNumExhaust = fmt.Errorf("no availabel number to allocate")

type NumAllocator struct {
	lock sync.Mutex
	// the bitmap will used end-start/8/1024/1024 MiB cache
	used      bitmap.Bitmap
	start     uint32
	end       uint32
	offset    uint32
	exhaust   bool
	setStatus func(string, bool, int)
	name      string
}

func NewNumAllocator(name string, start, end uint32) (*NumAllocator, error) {
	if start > end {
		return nil, fmt.Errorf("invalid param, start %#x can't bigger than end %#x", start, end)
	}
	return &NumAllocator{
		name:   name,
		used:   bitmap.Bitmap{},
		start:  start,
		end:    end,
		offset: 0,
	}, nil
}

func (a *NumAllocator) Valid(seqID uint32) error {
	if seqID < a.start {
		return fmt.Errorf("seqID %#x can't smaller than NumAllocator %s start %#x, it's invalid", seqID, a.name, a.start)
	}
	if seqID > a.end {
		return fmt.Errorf("seqID %#x can't bigger than NumAllocator %s end %#x, it's invalid", seqID, a.name, a.end)
	}
	return nil
}

func (a *NumAllocator) SetFunc(f func(string, bool, int)) {
	a.setStatus = f
	klog.Info("Success set setStatus func")
}

func (a *NumAllocator) SetStatus(name string, exhaust bool, used int) {
	if a.setStatus == nil {
		return
	}

	a.setStatus(name, exhaust, used)
}

func (a *NumAllocator) Allocate() (uint32, error) {
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.exhaust {
		return 0, ErrNumExhaust
	}
	oldOffset := a.offset
	for {
		if !a.used.Contains(a.offset) {
			res := a.start + a.offset
			a.used.Set(a.offset)
			a.offset = a.nextOffset(a.offset)
			a.SetStatus(a.name, a.exhaust, a.used.Count())
			klog.V(4).Infof("success to allocate number %x", res)
			return res, nil
		}
		a.offset = a.nextOffset(a.offset)
		if a.offset == oldOffset {
			klog.Errorf("allocate %s number has exhaust, oldOffset %x, used number count %x", a.name, oldOffset, a.used.Count())
			a.exhaust = true
			a.SetStatus(a.name, a.exhaust, a.used.Count())
			return 0, ErrNumExhaust
		}
	}
}

func (a *NumAllocator) Release(n uint32) {
	a.lock.Lock()
	defer a.lock.Unlock()

	if n < a.start || n > a.end {
		klog.Errorf("release invalid number %x, start %x, end %x", n, a.start, a.end)
		return
	}
	a.used.Remove(n - a.start)
	a.exhaust = false
	a.SetStatus(a.name, a.exhaust, a.used.Count())
	klog.V(4).Infof("success release number %x status: %v", n, a.used.Contains(n-a.start))
}

func (a *NumAllocator) Exhaust() bool {
	a.lock.Lock()
	defer a.lock.Unlock()

	return a.exhaust
}

func (a *NumAllocator) GetName() string {
	return a.name
}

func (a *NumAllocator) nextOffset(cur uint32) uint32 {
	return (cur + 1) % (a.end + 1 - a.start)
}

type FlowIDAlloctor struct {
	SeqIDAllocator *NumAllocator

	// flowid = moduleFix + roundNumber + seqID
	ModuleFix uint64
	SeqIDMask uint64
}

func NewFlowIDAlloctor(allocName string, start uint32, end uint32, moduleFix uint64) *FlowIDAlloctor {
	allo, err := NewNumAllocator(allocName, start, end)
	if err != nil {
		klog.Fatalf("failed to new rule seqID allocator: %s", err)
	}
	return &FlowIDAlloctor{
		SeqIDAllocator: allo,
		ModuleFix:      moduleFix,
		SeqIDMask:      1<<(64-constants.FlowIDModuleBits-constants.FlowIDReservedBits-constants.RoundNumberBits) - 1,
	}
}

func (f *FlowIDAlloctor) GetNumAlloctor() *NumAllocator {
	return f.SeqIDAllocator
}

func (f *FlowIDAlloctor) GetName() string {
	return f.SeqIDAllocator.GetName()
}

func (f *FlowIDAlloctor) Allocate() (uint32, error) {
	return f.SeqIDAllocator.Allocate()
}

func (f *FlowIDAlloctor) GetSeqIDByFlowID(flowID uint64) (uint32, error) {
	res := uint32(flowID & f.SeqIDMask)
	if err := f.SeqIDAllocator.Valid(res); err != nil {
		klog.Errorf("seqID from flowID %#x is invalid: %s", flowID, err)
		return 0, err
	}
	return res, nil
}

func (f *FlowIDAlloctor) Release(ctx context.Context, dels, ress []uint64) {
	log := ctrl.LoggerFrom(ctx)
	log.V(4).Info("release rule seq id", "all", dels, "res", ress)
	if len(dels) == 0 {
		return
	}
	delSeqIDs := sets.New[uint32]()
	resSeqIDs := sets.New[uint32]()
	for i := range dels {
		res, err := f.GetSeqIDByFlowID(dels[i])
		if err != nil {
			log.Error(err, "Skip release flowID for error", "flowID", dels[i])
			continue
		}
		delSeqIDs.Insert(res)
	}
	for i := range ress {
		res, err := f.GetSeqIDByFlowID(ress[i])
		if err != nil {
			log.Error(err, "Failed to get seqID from reserved flowID, skip it", "flowID", ress[i])
			continue
		}
		resSeqIDs.Insert(res)
	}
	needReleases := delSeqIDs.Difference(resSeqIDs)
	if len(needReleases) == 0 {
		return
	}
	for _, seqID := range needReleases.UnsortedList() {
		f.SeqIDAllocator.Release(seqID)
	}
	log.V(4).Info("success release module seq ids", "flowIDModule", f.GetName(), "seqIDs", needReleases)
}

func (f *FlowIDAlloctor) AssemblyFlowID(roundNumber uint64, seqID uint32) uint64 {
	return f.ModuleFix + roundNumber<<(64-constants.FlowIDModuleBits-constants.FlowIDReservedBits-constants.RoundNumberBits) + uint64(seqID)
}
