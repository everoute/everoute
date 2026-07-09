/*
Copyright 2026 The Everoute Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package datapath

import (
	"context"
	"sync"
	"time"

	"k8s.io/klog/v2"
)

type StartupFlowSync struct {
	lock sync.Mutex
	done chan struct{}

	manualCleanupRequestedCh chan struct{}

	status StartupFlowSyncStatus
}

type StartupFlowSyncStatus struct {
	NormalPolicyDone       bool
	GlobalPolicyDone       bool
	TrafficRedirectDone    bool
	ManualCleanupRequested bool
}

func NewStartupFlowSync() *StartupFlowSync {
	return &StartupFlowSync{
		done:                     make(chan struct{}),
		manualCleanupRequestedCh: make(chan struct{}),
	}
}

func (s *StartupFlowSync) MarkNormalPolicyDone() {
	if s == nil {
		return
	}
	s.markDone(&s.status.NormalPolicyDone, "normal policy")
}

func (s *StartupFlowSync) MarkGlobalPolicyDone() {
	if s == nil {
		return
	}
	s.markDone(&s.status.GlobalPolicyDone, "global policy")
}

func (s *StartupFlowSync) MarkTrafficRedirectDone() {
	if s == nil {
		return
	}
	s.markDone(&s.status.TrafficRedirectDone, "trafficredirect")
}

func (s *StartupFlowSync) NormalPolicyDone() bool {
	if s == nil {
		return true
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.status.NormalPolicyDone
}

func (s *StartupFlowSync) AllDone() bool {
	if s == nil {
		return true
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.status.NormalPolicyDone && s.status.GlobalPolicyDone && s.status.TrafficRedirectDone
}

func (s *StartupFlowSync) TriggerManualCleanup() bool {
	if s == nil {
		return false
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.status.ManualCleanupRequested {
		klog.Infof("Manual previous round cleanup requested, request already recorded")
		return false
	}
	s.status.ManualCleanupRequested = true
	close(s.manualCleanupRequestedCh)
	klog.Infof("Manual previous round cleanup requested")
	return true
}

func (s *StartupFlowSync) Status() StartupFlowSyncStatus {
	if s == nil {
		return StartupFlowSyncStatus{
			NormalPolicyDone:    true,
			GlobalPolicyDone:    true,
			TrafficRedirectDone: true,
		}
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.status
}

func (s *StartupFlowSync) WaitWithMinDelay(ctx context.Context, vdsID string, minDelay, logInterval time.Duration) error {
	if logInterval <= 0 {
		logInterval = time.Minute
	}

	ticker := time.NewTicker(logInterval)
	defer ticker.Stop()

	minDelayDone := minDelay <= 0
	var delayDoneCh <-chan time.Time
	if !minDelayDone {
		delayTimer := time.NewTimer(minDelay)
		defer delayTimer.Stop()
		delayDoneCh = delayTimer.C
	}

	startupFlowSyncDone := true
	var startupFlowSyncDoneCh <-chan struct{}
	var manualCleanupRequestedCh <-chan struct{}
	if s != nil {
		startupFlowSyncDone = s.AllDone()
		if !startupFlowSyncDone {
			startupFlowSyncDoneCh = s.done
		}
		manualCleanupRequestedCh = s.manualCleanupRequestedCh
	}
	if startupFlowSyncDone {
		startupFlowSyncDoneCh = nil
	}

	for {
		if minDelayDone && startupFlowSyncDone {
			s.logReadyToDeletePreviousRoundFlows(vdsID, minDelayDone)
			return nil
		}

		select {
		case <-ctx.Done():
			klog.Infof("Stop waiting before deleting previous round flows because context is done, vdsID: %s, err: %v", vdsID, ctx.Err())
			return ctx.Err()
		case <-manualCleanupRequestedCh:
			klog.Infof("Manual previous round cleanup request received, skip waiting startup flow sync and flow round clean delay")
			return nil
		case <-startupFlowSyncDoneCh:
			startupFlowSyncDone = true
			startupFlowSyncDoneCh = nil
			if minDelayDone {
				s.logReadyToDeletePreviousRoundFlows(vdsID, minDelayDone)
				return nil
			}
		case <-delayDoneCh:
			minDelayDone = true
			delayDoneCh = nil
			if startupFlowSyncDone {
				s.logReadyToDeletePreviousRoundFlows(vdsID, minDelayDone)
				return nil
			}
			status := s.Status()
			klog.Infof("Flow round clean delay elapsed, waiting startup flow sync before deleting previous round flows, "+
				"vdsID: %s, normalPolicyDone: %t, globalPolicyDone: %t, trafficRedirectDone: %t",
				vdsID, status.NormalPolicyDone, status.GlobalPolicyDone, status.TrafficRedirectDone)
		case <-ticker.C:
			status := s.Status()
			klog.Infof("Waiting before deleting previous round flows, vdsID: %s, flowRoundCleanDelayDone: %t, normalPolicyDone: %t, globalPolicyDone: %t, trafficRedirectDone: %t",
				vdsID, minDelayDone, status.NormalPolicyDone, status.GlobalPolicyDone, status.TrafficRedirectDone)
		}
	}
}

func (s *StartupFlowSync) logReadyToDeletePreviousRoundFlows(vdsID string, minDelayDone bool) {
	if s == nil {
		klog.Infof("Flow round clean delay completed and startup flow sync disabled, ready to delete previous round flows, "+
			"vdsID: %s, flowRoundCleanDelayDone: %t", vdsID, minDelayDone)
		return
	}
	status := s.Status()
	klog.Infof("Startup flow sync and flow round clean delay completed, ready to delete previous round flows, "+
		"vdsID: %s, flowRoundCleanDelayDone: %t, normalPolicyDone: %t, globalPolicyDone: %t, trafficRedirectDone: %t",
		vdsID, minDelayDone, status.NormalPolicyDone, status.GlobalPolicyDone, status.TrafficRedirectDone)
}

func (s *StartupFlowSync) markDone(done *bool, name string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if *done {
		return
	}
	*done = true
	klog.Infof("Startup %s flow sync done", name)
	if s.status.NormalPolicyDone && s.status.GlobalPolicyDone && s.status.TrafficRedirectDone {
		close(s.done)
	}
}
