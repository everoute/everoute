package conntrack

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog"
)

type UpdateConntrackFlowFunc = func(flow *netlink.ConntrackFlow) (updated bool)

const (
	DefaultFlushTimeout = 5 * time.Minute
	DefaultV4BufferSize = 10000
	DefaultV6BufferSize = 10000
	DefaultUpdateDelay  = 500 * time.Millisecond
)

type Manager struct {
	flushTimeout      time.Duration
	flushingConntrack atomic.Bool
	// FIXME: adapt more matchers
	v4MatcherChan chan TupleMatcher
	v6MatcherChan chan TupleMatcher
}

func NewManager(flushTimeout time.Duration, v4BufferSize, v6BufferSize int) *Manager {
	if flushTimeout == 0 {
		flushTimeout = DefaultFlushTimeout
	}

	if v4BufferSize <= 0 {
		v4BufferSize = DefaultV4BufferSize
	}
	if v6BufferSize <= 0 {
		v6BufferSize = DefaultV6BufferSize
	}
	v4MatcherChan := make(chan TupleMatcher, v4BufferSize)
	v6MatcherChan := make(chan TupleMatcher, v6BufferSize)

	return &Manager{
		flushTimeout:  flushTimeout,
		v4MatcherChan: v4MatcherChan,
		v6MatcherChan: v6MatcherChan,
	}
}

func (m *Manager) StartUpdateConntrackFlows(
	ctx context.Context,
	updateFunc UpdateConntrackFlowFunc,
	updateDelay time.Duration,
) {
	pool := sync.Pool{
		New: func() any {
			return &netlink.ConntrackFlow{}
		},
	}
	conntrackFlowAllocator := func() *netlink.ConntrackFlow {
		return pool.Get().(*netlink.ConntrackFlow)
	}
	conntrackFlowDeallocator := func(flow *netlink.ConntrackFlow) {
		pool.Put(flow)
	}
	go m.updateConntrackFlowsLoop(
		ctx, unix.AF_INET,
		conntrackFlowAllocator, conntrackFlowDeallocator,
		updateFunc, updateDelay,
	)
	go m.updateConntrackFlowsLoop(
		ctx, unix.AF_INET6,
		conntrackFlowAllocator, conntrackFlowDeallocator,
		updateFunc, updateDelay,
	)
}

func (m *Manager) updateConntrackFlowsLoop(
	ctx context.Context, family uint8,
	conntrackFlowAllocator func() *netlink.ConntrackFlow,
	conntrackFlowDeallocator func(*netlink.ConntrackFlow),
	updateFunc UpdateConntrackFlowFunc,
	updateDelay time.Duration,
) {
	var ctMatcherChan chan TupleMatcher
	switch family {
	case unix.AF_INET:
		ctMatcherChan = m.v4MatcherChan
	case unix.AF_INET6:
		ctMatcherChan = m.v6MatcherChan
	default:
		klog.Fatalf("invalid family: %d", family)
	}
	for {
		exit := updateConntrackFlows(
			ctx, family,
			ctMatcherChan,
			conntrackFlowAllocator, conntrackFlowDeallocator,
			updateFunc,
			updateDelay,
		)
		if exit {
			break
		}
	}
}

// loop body of clearConntrackFlowsLoop
func updateConntrackFlows(ctx context.Context,
	family uint8,
	ctMatcherChan chan TupleMatcher,
	conntrackFlowAllocator func() *netlink.ConntrackFlow,
	conntrackFlowDeallocator func(*netlink.ConntrackFlow),
	updateFunc UpdateConntrackFlowFunc,
	updateDelay time.Duration,
) bool {
	familyStr := ""
	switch family {
	case unix.AF_INET:
		familyStr = "IPv4"
	case unix.AF_INET6:
		familyStr = "IPv6"
	default:
		familyStr = strconv.Itoa(int(family))
	}
	defer func() {
		if r := recover(); r != nil {
			klog.Errorf("update conntrack flows panic, family: %s, err: %v", familyStr, r)
		}
	}()
	select {
	case <-ctx.Done():
		return true
	case m := <-ctMatcherChan:
		if updateDelay > 0 {
			time.Sleep(updateDelay)
		}
		ids := sets.NewString(m.GetID())
		// receive matchers from ctMatcherChan
		currentBufferredMatchers := len(ctMatcherChan) + 1
		matchers := make([]TupleMatcher, currentBufferredMatchers)
		matchers[0] = m
		i := 1
		for i < currentBufferredMatchers {
			select {
			case <-ctx.Done():
				return true
			case matcher := <-ctMatcherChan:
				if ids.Has(matcher.GetID()) {
					continue
				}
				ids.Insert(matcher.GetID())
				matchers[i] = matcher
				i++
			default:
				goto endReceive
			}
		}
	endReceive:
		matchers = matchers[:i]

		cookedMatcher := CookTupleMatcherBatch(matchers)

		dumpCount, matchCount, successCount, failureCount, err := UpdateConntrackFlows(
			family,
			&cookedMatcher,
			conntrackFlowAllocator, conntrackFlowDeallocator,
			updateFunc,
		)
		if err != nil {
			klog.Errorf("update conntrack flows error, family: %d, err: %v", family, err)
			return false
		}
		if matchCount > 0 || successCount > 0 || failureCount > 0 {
			klog.Infof("updated conntrack flows for matchers [%v], family: %s, dump: %d, match: %d, success: %d, failure: %d",
				cookedMatcher.IDs, familyStr, dumpCount, matchCount, successCount, failureCount,
			)
		}
		return false
	}
}

// AsyncUpdateConntrackFlows updates conntrack flows asynchronously
// if skipOnFlushing is true, it will skip updating conntrack flows if the conntrack is currently flushing
// if skipOnFlushing is false, it will update conntrack flows even if the conntrack is currently flushing
// onFull is called when the conntrack is full and the update is skipped
// this function requires StartUpdateConntrackFlows to be called before using it
func (m *Manager) AsyncUpdateConntrackFlows(family uint8, matcher TupleMatcher, onFull func(), skipOnFlushing bool) {
	if skipOnFlushing && m.flushingConntrack.Load() {
		// skip update conntrack flows
		return
	}
	switch family {
	case unix.AF_INET:
		select {
		case m.v4MatcherChan <- matcher:
		default:
			onFull()
		}
	case unix.AF_INET6:
		select {
		case m.v6MatcherChan <- matcher:
		default:
			onFull()
		}
	default:
		klog.Fatalf("invalid family: %d", family)
	}
}

func (m *Manager) ClearBuffer() {
	for {
		select {
		case <-m.v4MatcherChan:
		case <-m.v6MatcherChan:
		default:
			return
		}
	}
}

func (m *Manager) AsyncFlushConntrackFlows() {
	// cas mark flushingConntrack
	if !m.flushingConntrack.CompareAndSwap(false, true) {
		// skip
		return
	}
	stopped := make(chan struct{})
	go func() {
		defer m.flushingConntrack.Store(false)
		defer close(stopped)
		err := netlink.ConntrackTableFlush(netlink.ConntrackTable)
		if err != nil {
			klog.Errorf("flush conntrack flows error, err: %s", err)
		}
	}()
	// wait for flush to complete or timeout
	go func() {
		select {
		case <-stopped:
			return
		case <-time.After(m.flushTimeout):
			klog.Fatalf("flush conntrack flows timeout, flushTimeout: %s", m.flushTimeout)
		}
	}()
}

// update conntrack flows
// return: dumpCount, matchCount, successCount, failureCount, error
func UpdateConntrackFlows(
	family uint8, matcher Matcher,
	conntrackFlowAllocator func() *netlink.ConntrackFlow,
	conntrackFlowDeallocator func(*netlink.ConntrackFlow),
	updateFunc UpdateConntrackFlowFunc,
) (int, int, int, int, error) {
	if family != unix.AF_INET && family != unix.AF_INET6 {
		klog.Errorf("invalid family: %d", family)
		return 0, 0, 0, 0, fmt.Errorf("invalid family: %d", family)
	}
	// use for logging
	dumpCount := 0
	matchCount := 0
	successCount := 0
	failureCount := 0

	// dump conntrack flows and update conntrack labels
	/*
		update goroutine: wait for receive conntrack flows or end signal and update conntrack labels
		dump goroutine: dump conntrack flows and close conntrackFlowChan
		main goroutine: receive from conntrackFlowChan until channel is closed
	*/
	conntrackFlowChan := make(chan *netlink.ConntrackFlow, 10000)
	go func() { // dump goroutine
		defer close(conntrackFlowChan)
		err := netlink.ConntrackTableListStream(netlink.ConntrackTable, netlink.InetFamily(family), conntrackFlowChan, conntrackFlowAllocator)
		if err != nil {
			klog.Errorf("get conntrack flows error, err: %s", err)
			return
		}
	}()

	// alloc a netlink connection
	handle, err := netlink.NewHandle(unix.NETLINK_NETFILTER)
	if err != nil {
		klog.Errorf("create netlink handle error, err: %s", err)
		return 0, 0, 0, 0, err
	}
	defer handle.Close()

	// create a conntrack update request
	request := handle.NewConntrackUpdateRequest(netlink.ConntrackTable, netlink.InetFamily(family), false)

	// make a buffer as allocator
	rtAttrs := make([]*nl.RtAttr, 0)
	rtAttrIndex := 0
	// serialize buffer
	buffer := make([]nl.NetlinkRequestData, 32)

	// process conntrack flows
	for flow := range conntrackFlowChan {
		if flow == nil {
			continue // never happen
		}
		dumpCount++
		if matcher != nil && matcher.MatchConntrackFlow(flow) {
			matchCount++
			updated := updateFunc(flow)
			if !updated {
				continue
			}
			rtAttrIndex = 0
			newRtAttr := func(attrType int, data []byte) *nl.RtAttr {
				if rtAttrIndex >= len(rtAttrs) {
					rtAttr := nl.NewRtAttr(attrType, data)
					rtAttrs = append(rtAttrs, rtAttr)
					rtAttrIndex++
					return rtAttr
				}
				attr := rtAttrs[rtAttrIndex]
				*attr = nl.RtAttr{}
				attr.RtAttr.Type = uint16(attrType)
				attr.Data = data
				rtAttrIndex++
				return attr
			}
			err := handle.ExecuteConntrackRequest(
				request,
				flow,
				newRtAttr, buffer,
				false, // ignore error
			)
			// the error is ignored, but we check it for safety
			if err != nil {
				if err != syscall.ENOENT {
					klog.Errorf("update conntrack flow %s error, old labels %x/%x, error: %s",
						flow.String(), flow.Labels, flow.LabelsMask, err,
					)
					failureCount++
					continue
				}
			} else {
				successCount++
			}
		}
		conntrackFlowDeallocator(flow)
	}
	return dumpCount, matchCount, successCount, failureCount, nil
}

func DumpConntrackFlows(
	family uint8, matcher Matcher,
	conntrackFlowAllocator func() *netlink.ConntrackFlow,
	conntrackFlowDeallocator func(*netlink.ConntrackFlow),
	dumpFunc func(*netlink.ConntrackFlow) error,
) (int, int, error) {
	if family != unix.AF_INET && family != unix.AF_INET6 {
		klog.Errorf("invalid family: %d", family)
		return 0, 0, fmt.Errorf("invalid family: %d", family)
	}
	if conntrackFlowAllocator == nil {
		return 0, 0, fmt.Errorf("conntrackFlowAllocator must not be nil")
	}
	if dumpFunc == nil {
		return 0, 0, fmt.Errorf("dumpFunc must not be nil")
	}

	conntrackFlowChan := make(chan *netlink.ConntrackFlow, 10000)
	errCh := make(chan error, 1)
	go func() {
		defer close(conntrackFlowChan)
		errCh <- netlink.ConntrackTableListStream(
			netlink.ConntrackTable,
			netlink.InetFamily(family),
			conntrackFlowChan,
			conntrackFlowAllocator,
		)
	}()

	dumpCount := 0
	matchCount := 0
	var dumpErr error
	for flow := range conntrackFlowChan {
		if flow == nil {
			continue
		}
		dumpCount++
		if matcher == nil || matcher.MatchConntrackFlow(flow) {
			matchCount++
			if dumpErr == nil {
				dumpErr = dumpFunc(flow)
			}
		}
		if conntrackFlowDeallocator != nil {
			conntrackFlowDeallocator(flow)
		}
	}

	return dumpCount, matchCount, errors.Join(<-errCh, dumpErr)
}

func DeleteConntrackFlows(
	family uint8, matcher Matcher,
	conntrackFlowAllocator func() *netlink.ConntrackFlow,
	conntrackFlowDeallocator func(*netlink.ConntrackFlow),
) (int, int, int, int, error) {
	if family != unix.AF_INET && family != unix.AF_INET6 {
		klog.Errorf("invalid family: %d", family)
		return 0, 0, 0, 0, fmt.Errorf("invalid family: %d", family)
	}
	if conntrackFlowAllocator == nil {
		return 0, 0, 0, 0, fmt.Errorf("conntrackFlowAllocator must not be nil")
	}

	handle, err := netlink.NewHandle(unix.NETLINK_NETFILTER)
	if err != nil {
		klog.Errorf("create netlink handle error, err: %s", err)
		return 0, 0, 0, 0, err
	}
	defer handle.Close()

	request := handle.NewConntrackUpdateRequest(netlink.ConntrackTable, netlink.InetFamily(family), true)
	request.NlMsghdr.Type = uint16((int(netlink.ConntrackTable) << 8) | nl.IPCTNL_MSG_CT_DELETE)
	request.NlMsghdr.Flags = unix.NLM_F_REQUEST | unix.NLM_F_ACK

	rtAttrs := make([]*nl.RtAttr, 0)
	rtAttrIndex := 0
	buffer := make([]nl.NetlinkRequestData, 32)

	successCount := 0
	failureCount := 0
	dumpCount, matchCount, err := DumpConntrackFlows(
		family,
		matcher,
		conntrackFlowAllocator,
		conntrackFlowDeallocator,
		func(flow *netlink.ConntrackFlow) error {
			rtAttrIndex = 0
			newRtAttr := func(attrType int, data []byte) *nl.RtAttr {
				if rtAttrIndex >= len(rtAttrs) {
					rtAttr := nl.NewRtAttr(attrType, data)
					rtAttrs = append(rtAttrs, rtAttr)
					rtAttrIndex++
					return rtAttr
				}
				attr := rtAttrs[rtAttrIndex]
				*attr = nl.RtAttr{}
				attr.RtAttr.Type = uint16(attrType)
				attr.Data = data
				rtAttrIndex++
				return attr
			}
			err := handle.ExecuteConntrackRequest(
				request,
				flow,
				newRtAttr, buffer,
				true,
			)
			if err != nil {
				if !errors.Is(err, syscall.ENOENT) {
					failureCount++
					return nil
				}
			}
			successCount++
			return nil
		},
	)
	if failureCount > 0 {
		err = errors.Join(err, fmt.Errorf("failed to delete %d conntrack flows", failureCount))
	}
	return dumpCount, matchCount, successCount, failureCount, err
}
