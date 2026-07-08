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

	normalPolicyDone    bool
	globalPolicyDone    bool
	trafficRedirectDone bool
}

func NewStartupFlowSync() *StartupFlowSync {
	return &StartupFlowSync{
		done: make(chan struct{}),
	}
}

func (s *StartupFlowSync) MarkNormalPolicyDone() {
	if s == nil {
		return
	}
	s.markDone(&s.normalPolicyDone, "normal policy")
}

func (s *StartupFlowSync) MarkGlobalPolicyDone() {
	if s == nil {
		return
	}
	s.markDone(&s.globalPolicyDone, "global policy")
}

func (s *StartupFlowSync) MarkTrafficRedirectDone() {
	if s == nil {
		return
	}
	s.markDone(&s.trafficRedirectDone, "trafficredirect")
}

func (s *StartupFlowSync) NormalPolicyDone() bool {
	if s == nil {
		return true
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.normalPolicyDone
}

func (s *StartupFlowSync) AllDone() bool {
	if s == nil {
		return true
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.normalPolicyDone && s.globalPolicyDone && s.trafficRedirectDone
}

func (s *StartupFlowSync) WaitWithMinDelay(ctx context.Context, minDelay, logInterval time.Duration) error {
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
	if s != nil {
		startupFlowSyncDone = s.AllDone()
		if !startupFlowSyncDone {
			startupFlowSyncDoneCh = s.done
		}
	}
	if startupFlowSyncDone {
		startupFlowSyncDoneCh = nil
	}

	for {
		if minDelayDone && startupFlowSyncDone {
			s.logReadyToDeletePreviousRoundFlows(minDelayDone)
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-startupFlowSyncDoneCh:
			startupFlowSyncDone = true
			startupFlowSyncDoneCh = nil
			if minDelayDone {
				s.logReadyToDeletePreviousRoundFlows(minDelayDone)
				return nil
			}
		case <-delayDoneCh:
			minDelayDone = true
			delayDoneCh = nil
			if startupFlowSyncDone {
				s.logReadyToDeletePreviousRoundFlows(minDelayDone)
				return nil
			}
			normalPolicyDone, globalPolicyDone, trafficRedirectDone := s.doneStatus()
			klog.Infof("Flow round clean delay elapsed, waiting startup flow sync before deleting previous round flows, "+
				"normalPolicyDone: %t, globalPolicyDone: %t, trafficRedirectDone: %t",
				normalPolicyDone, globalPolicyDone, trafficRedirectDone)
		case <-ticker.C:
			normalPolicyDone, globalPolicyDone, trafficRedirectDone := s.doneStatus()
			klog.Infof("Waiting before deleting previous round flows, flowRoundCleanDelayDone: %t, normalPolicyDone: %t, globalPolicyDone: %t, trafficRedirectDone: %t",
				minDelayDone, normalPolicyDone, globalPolicyDone, trafficRedirectDone)
		}
	}
}

func (s *StartupFlowSync) logReadyToDeletePreviousRoundFlows(minDelayDone bool) {
	if s == nil {
		klog.Infof("Flow round clean delay completed and startup flow sync disabled, ready to delete previous round flows, "+
			"flowRoundCleanDelayDone: %t", minDelayDone)
		return
	}
	normalPolicyDone, globalPolicyDone, trafficRedirectDone := s.doneStatus()
	klog.Infof("Startup flow sync and flow round clean delay completed, ready to delete previous round flows, "+
		"flowRoundCleanDelayDone: %t, normalPolicyDone: %t, globalPolicyDone: %t, trafficRedirectDone: %t",
		minDelayDone, normalPolicyDone, globalPolicyDone, trafficRedirectDone)
}

func (s *StartupFlowSync) markDone(done *bool, name string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if *done {
		return
	}
	*done = true
	klog.Infof("Startup %s flow sync done", name)
	if s.normalPolicyDone && s.globalPolicyDone && s.trafficRedirectDone {
		close(s.done)
	}
}

func (s *StartupFlowSync) doneStatus() (normalPolicyDone, globalPolicyDone, trafficRedirectDone bool) {
	if s == nil {
		return true, true, true
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.normalPolicyDone, s.globalPolicyDone, s.trafficRedirectDone
}
