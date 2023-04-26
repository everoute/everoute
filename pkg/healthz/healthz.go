/*
Copyright 2022 The Everoute Authors.

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

package healthz

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"k8s.io/apiserver/pkg/server/healthz"
)

// PingHealthz returns true automatically when checked
var PingHealthz = healthz.PingHealthz

// LogHealthz returns true if logging is not blocked
var LogHealthz = healthz.LogHealthz

// NewInformerSyncHealthz returns a new HealthChecker that will pass only if
// all informers in the given cacheSyncWaiter sync.
var NewInformerSyncHealthz = healthz.NewInformerSyncHealthz

// NamedCheck returns a healthz checker for the given name and function.
var NamedCheck = healthz.NamedCheck

type cacheSyncWaiter interface {
	WaitForCacheSync(stopCh <-chan struct{}) bool
}

type cacheSync struct {
	cacheSynced     atomic.Value
	checkOnce       sync.Once
	cacheSyncWaiter cacheSyncWaiter
}

var _ healthz.HealthChecker = &cacheSync{}

// NewCacheSyncHealthz returns a new HealthChecker that will pass on cache sync.
func NewCacheSyncHealthz(cacheSyncWaiter cacheSyncWaiter) healthz.HealthChecker {
	return &cacheSync{
		cacheSyncWaiter: cacheSyncWaiter,
	}
}

func (i *cacheSync) Name() string {
	return "cache-sync"
}

func (i *cacheSync) Check(_ *http.Request) error {
	// WaitForCacheSync block until the cache synced.
	// We check once and wait the cache synced.
	go i.checkOnce.Do(func() {
		stopCh := make(chan struct{})
		defer close(stopCh)
		i.cacheSynced.Store(i.cacheSyncWaiter.WaitForCacheSync(stopCh))
	})

	if synced := i.cacheSynced.Load(); synced == nil || !synced.(bool) {
		return fmt.Errorf("cache not started yet")
	}
	return nil
}

type loadModule struct {
	Modules []string
}

var _ healthz.HealthChecker = &loadModule{}

func NewLoadModuleHealthz(modules []string) healthz.HealthChecker {
	h := &loadModule{Modules: make([]string, 0, len(modules))}
	h.Modules = append(h.Modules, modules...)
	return h
}

func (l *loadModule) Name() string {
	return "load-module"
}

func (l *loadModule) Check(_ *http.Request) error {
	file, err := os.Open("/proc/modules")
	if err != nil {
		return fmt.Errorf("failed to open /proc/modules: %s", err)
	}
	defer file.Close()

	moduleLoad := make(map[string]bool, 4)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		s := strings.Split(scanner.Text(), " ")
		name := s[0]
		for i := range l.Modules {
			if name == l.Modules[i] {
				moduleLoad[name] = true
			}
		}
	}

	for _, module := range l.Modules {
		if !moduleLoad[module] {
			return fmt.Errorf("os doesn't load module %s", module)
		}
	}
	return nil
}

// WithEnable returns checker when enable is nill or true, else returns nopHealthz.
func WithEnable(enable *bool, checker healthz.HealthChecker) healthz.HealthChecker {
	if enable == nil || *enable {
		return checker
	}
	return healthz.NamedCheck(checker.Name(), func(r *http.Request) error {
		return nil
	})
}

// InstallHandler registers handlers for health checking on the path
// "/healthz" to server.
func InstallHandler(s server, checks ...healthz.HealthChecker) {
	healthz.InstallHandler(muxFunc(s.Register), checks...)
}

// server is an interface describing the methods InstallHandler requires.
type server interface {
	Register(pattern string, handler http.Handler)
}

type muxFunc func(pattern string, handler http.Handler)

func (mux muxFunc) Handle(pattern string, handler http.Handler) {
	mux(pattern, handler)
}
