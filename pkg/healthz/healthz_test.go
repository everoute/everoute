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

package healthz_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/everoute/everoute/pkg/healthz"
)

func TestInstallHandler(t *testing.T) {
	mux := http.NewServeMux()
	healthz.InstallHandler(serverFunc(mux.Handle))
	req, err := http.NewRequestWithContext(context.Background(), "GET", "https://example.com/healthz", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected %v, got %v", http.StatusOK, w.Code)
	}
	c := w.Header().Get("Content-Type")
	if c != "text/plain; charset=utf-8" {
		t.Errorf("expected %v, got %v", "text/plain", c)
	}
	if w.Body.String() != "ok" {
		t.Errorf("expected %v, got %v", "ok", w.Body.String())
	}
}

func TestCacheSyncHealthChecker(t *testing.T) {
	t.Run("test that check returns nil when cache are started", func(t *testing.T) {
		RegisterTestingT(t)
		healthChecker := healthz.NewCacheSyncHealthz(cacheSyncWaiterStub{true})

		checkFunc := func() error { return healthChecker.Check(nil) }
		Eventually(checkFunc).ShouldNot(HaveOccurred())
	})

	t.Run("test that check returns err when the cache not started", func(t *testing.T) {
		healthChecker := healthz.NewCacheSyncHealthz(cacheSyncWaiterStub{false})

		err := healthChecker.Check(nil)
		if err == nil {
			t.Errorf("expected error, got: %v", err)
		}
	})
}

func TestWithEnable(t *testing.T) {
	var errUnhealth = errors.New("unhealth")
	var unhealthChecker = healthz.NamedCheck("unhealth-checker", func(r *http.Request) error {
		return errUnhealth
	})

	t.Run("test that enable is nil", func(t *testing.T) {
		checker := healthz.WithEnable(nil, unhealthChecker)
		err := checker.Check(nil)
		if !errors.Is(err, errUnhealth) {
			t.Errorf("Got %v, expected %v", err, errUnhealth)
		}
	})

	t.Run("test that enable is false", func(t *testing.T) {
		checker := healthz.WithEnable(new(bool), unhealthChecker)
		err := checker.Check(nil)
		if err != nil {
			t.Errorf("Got %v, expected no error", err)
		}
	})

	t.Run("test that enable is true", func(t *testing.T) {
		var boolTrue = true
		checker := healthz.WithEnable(&boolTrue, unhealthChecker)
		err := checker.Check(nil)
		if !errors.Is(err, errUnhealth) {
			t.Errorf("Got %v, expected %v", err, errUnhealth)
		}
	})
}

type serverFunc func(pattern string, handler http.Handler)

func (server serverFunc) Register(pattern string, handler http.Handler) {
	server(pattern, handler)
}

type cacheSyncWaiterStub struct {
	started bool
}

// WaitForCacheSync is a stub implementation of the corresponding func
// that simply returns the value passed during stub initialization.
func (s cacheSyncWaiterStub) WaitForCacheSync(_ <-chan struct{}) bool {
	return s.started
}
