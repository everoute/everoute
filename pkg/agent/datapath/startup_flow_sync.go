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
	normalPolicyOnce    sync.Once
	globalPolicyOnce    sync.Once
	trafficRedirectOnce sync.Once

	normalPolicyDone    chan struct{}
	globalPolicyDone    chan struct{}
	trafficRedirectDone chan struct{}
}

type StartupFlowSyncStatus struct {
	NormalPolicyDone    bool
	GlobalPolicyDone    bool
	TrafficRedirectDone bool
}

func NewStartupFlowSync(enablePolicy, enableTrafficRedirect bool) *StartupFlowSync {
	s := &StartupFlowSync{
		normalPolicyDone:    make(chan struct{}),
		globalPolicyDone:    make(chan struct{}),
		trafficRedirectDone: make(chan struct{}),
	}
	if !enablePolicy {
		s.MarkNormalPolicyDone()
		s.MarkGlobalPolicyDone()
	}
	if !enableTrafficRedirect {
		s.MarkTrafficRedirectDone()
	}
	return s
}

func (s *StartupFlowSync) MarkNormalPolicyDone() {
	if s == nil {
		return
	}
	s.normalPolicyOnce.Do(func() {
		klog.Info("Startup normal policy flow sync done")
		close(s.normalPolicyDone)
	})
}

func (s *StartupFlowSync) MarkGlobalPolicyDone() {
	if s == nil {
		return
	}
	s.globalPolicyOnce.Do(func() {
		klog.Info("Startup global policy flow sync done")
		close(s.globalPolicyDone)
	})
}

func (s *StartupFlowSync) MarkTrafficRedirectDone() {
	if s == nil {
		return
	}
	s.trafficRedirectOnce.Do(func() {
		klog.Info("Startup trafficredirect flow sync done")
		close(s.trafficRedirectDone)
	})
}

func (s *StartupFlowSync) NormalPolicyDone() bool {
	if s == nil {
		return true
	}
	return chanClosed(s.normalPolicyDone)
}

func (s *StartupFlowSync) GlobalPolicyDone() bool {
	if s == nil {
		return true
	}
	return chanClosed(s.globalPolicyDone)
}

func (s *StartupFlowSync) TrafficRedirectDone() bool {
	if s == nil {
		return true
	}
	return chanClosed(s.trafficRedirectDone)
}

func (s *StartupFlowSync) AllDone() bool {
	if s == nil {
		return true
	}
	return s.NormalPolicyDone() && s.GlobalPolicyDone() && s.TrafficRedirectDone()
}

func (s *StartupFlowSync) Status() StartupFlowSyncStatus {
	return StartupFlowSyncStatus{
		NormalPolicyDone:    s.NormalPolicyDone(),
		GlobalPolicyDone:    s.GlobalPolicyDone(),
		TrafficRedirectDone: s.TrafficRedirectDone(),
	}
}

func (s *StartupFlowSync) Wait(ctx context.Context, logInterval time.Duration) error {
	if s == nil || s.AllDone() {
		return nil
	}
	if logInterval <= 0 {
		logInterval = time.Minute
	}
	ticker := time.NewTicker(logInterval)
	defer ticker.Stop()

	for {
		if s.AllDone() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			status := s.Status()
			klog.Infof("Waiting startup flow sync before deleting previous round flows, normalPolicyDone: %t, globalPolicyDone: %t, trafficRedirectDone: %t",
				status.NormalPolicyDone, status.GlobalPolicyDone, status.TrafficRedirectDone)
		}
	}
}

func chanClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
