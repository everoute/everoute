package datapath

import (
	"testing"
)

func TestNumAllocator(t *testing.T) {
	a, err := NewNumAllocator(20, 10)
	if err == nil || a != nil {
		t.Errorf("should new num allocator failed when start biggger than end, but success")
	}

	a, err = NewNumAllocator(2, 4)
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
