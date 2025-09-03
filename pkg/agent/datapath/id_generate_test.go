package datapath

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	trconst "github.com/everoute/everoute/pkg/constants/tr"
)

func TestNumAllocator(t *testing.T) {
	a, err := NewNumAllocator("test1", 20, 10)
	if err == nil || a != nil {
		t.Errorf("should new num allocator failed when start biggger than end, but success")
	}

	a, err = NewNumAllocator("test2", 2, 4)
	if err != nil || a == nil {
		t.Errorf("should new num allocator success, but failed")
	}

	var r uint32
	r, err = a.Allocate()
	if err != nil {
		t.Errorf("should success allocate num, but failed: %s", err)
	}
	if r != 2 {
		t.Errorf("unexpect allocate num, expect is 2, real is %d", r)
	}

	r, err = a.Allocate()
	if err != nil {
		t.Errorf("should success allocate num, but failed: %s", err)
	}
	if r != 3 {
		t.Errorf("unexpect allocate num, expect is 3, real is %d", r)
	}

	r, err = a.Allocate()
	if err != nil {
		t.Errorf("should success allocate num, but failed: %s", err)
	}
	if r != 4 {
		t.Errorf("unexpect allocate num, expect is 4, real is %d", r)
	}

	r, err = a.Allocate()
	if err == nil || err != ErrNumExhaust {
		t.Errorf("expect err is %s, real is: %s", ErrNumExhaust, err)
	}

	a.Release(3)
	r, err = a.Allocate()
	if err != nil {
		t.Errorf("should success allocate num, but failed: %s", err)
	}
	if r != 3 {
		t.Errorf("unexpect allocate num, expect is 3, real is %d", r)
	}
}

func TestFlowIDAlloctor(t *testing.T) {
	ctx := context.Background()
	// test policy alloctor
	allo := NewFlowIDAlloctor(MSModuleName, uint32(CookieRuleFix), uint32(CookieRuleFix)+0xff, 0x0)
	sid, err := allo.Allocate()
	assert.Nil(t, err)
	assert.Equal(t, sid, uint32(0x0800_0000))
	fid := allo.AssemblyFlowID(4, sid)
	assert.Equal(t, fid, uint64(0x4800_0000))
	sid2, err := allo.GetSeqIDByFlowID(0x5800_0000)
	assert.Nil(t, err)
	assert.Equal(t, sid2, sid)
	assert.False(t, allo.GetNumAlloctor().Exhaust())

	for i := 0; i < 0xfe; i++ {
		sid, err = allo.Allocate()
		assert.Nil(t, err)
	}
	sid, err = allo.Allocate()
	assert.Nil(t, err)
	assert.Equal(t, sid, uint32(0x0800_00ff))
	fid = allo.AssemblyFlowID(3, sid)
	assert.Equal(t, fid, uint64(0x3800_00ff))
	sid2, err = allo.GetSeqIDByFlowID(fid)
	assert.Nil(t, err)
	assert.Equal(t, sid2, sid)
	sid, err = allo.Allocate()
	assert.Equal(t, err, ErrNumExhaust)
	assert.True(t, allo.GetNumAlloctor().Exhaust())

	allo.Release(ctx, []uint64{0x3800_0015, 0x5800_0025, 0x4800_0000}, []uint64{0x0800_0000})
	assert.False(t, allo.GetNumAlloctor().Exhaust())
	sid, err = allo.Allocate()
	assert.Nil(t, err)
	assert.Equal(t, sid, uint32(0x0800_0015))

	sid2, err = allo.GetSeqIDByFlowID(0x4900_0003)
	assert.NotNil(t, err)

	// test tr rule alloctor
	allo = NewFlowIDAlloctor(TRModuleName, trconst.FlowIDRuleBegin, trconst.FlowIDRuleBegin+0xff, trconst.FlowIDPrefix)
	sid, err = allo.Allocate()
	assert.Nil(t, err)
	assert.Equal(t, sid, uint32(0x0800_0000))
	fid = allo.AssemblyFlowID(4, sid)
	assert.Equal(t, fid, uint64(0x2000_0000_4800_0000))
	sid2, err = allo.GetSeqIDByFlowID(0x2000_0000_4800_0000)
	assert.Nil(t, err)
	assert.Equal(t, sid2, sid)
	assert.False(t, allo.GetNumAlloctor().Exhaust())

	for i := 0; i < 0xfe; i++ {
		sid, err = allo.Allocate()
		assert.Nil(t, err)
	}
	sid, err = allo.Allocate()
	assert.Nil(t, err)
	assert.Equal(t, sid, uint32(0x800_00ff))
	fid = allo.AssemblyFlowID(3, sid)
	assert.Equal(t, fid, uint64(0x2000_0000_3800_00ff))
	sid2, err = allo.GetSeqIDByFlowID(fid)
	assert.Nil(t, err)
	assert.Equal(t, sid2, sid)
	sid, err = allo.Allocate()
	assert.Equal(t, err, ErrNumExhaust)
	assert.True(t, allo.GetNumAlloctor().Exhaust())

	allo.Release(ctx, []uint64{0x2000_0000_3800_0005, 0x2000_0000_5800_0003, 0x2000_0000_0800_0000}, []uint64{})
	assert.False(t, allo.GetNumAlloctor().Exhaust())
	sid, err = allo.Allocate()
	assert.Nil(t, err)
	assert.Equal(t, sid, uint32(0x0800_0000))

	sid2, err = allo.GetSeqIDByFlowID(0x4700_0003)
	assert.NotNil(t, err)
}
