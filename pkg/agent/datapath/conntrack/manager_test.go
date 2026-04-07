//go:build linux

package conntrack

import (
	"sync"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestUpdateConntrackFlows_NoPanicOnChannelClose(t *testing.T) {
	var pool sync.Pool
	pool.New = func() any {
		return &netlink.ConntrackFlow{}
	}
	allocator := func() *netlink.ConntrackFlow {
		return pool.Get().(*netlink.ConntrackFlow)
	}
	deallocator := func(flow *netlink.ConntrackFlow) {
		pool.Put(flow)
	}
	updateFunc := func(_ *netlink.ConntrackFlow) bool {
		return false
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("UpdateConntrackFlows should not panic, got: %v", r)
		}
	}()

	_, _, _, _, err := UpdateConntrackFlows(
		unix.AF_INET,
		CookMatcherBatch(nil),
		allocator,
		deallocator,
		updateFunc,
	)
	if err != nil {
		t.Logf("UpdateConntrackFlows returned error: %v", err)
	}
}
