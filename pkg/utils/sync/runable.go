/*
Copyright 2023 The Everoute Authors.

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

package sync

import (
	"context"
	"fmt"
	"sync"
)

// Runables manage a setof runables and allows batch start them
type Runables struct {
	mu       sync.Mutex
	start    bool
	runables []func(ctx context.Context) error
}

// Push one runable function to Runables
func (r *Runables) Push(f func(ctx context.Context) error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.start {
		panic("push to a started runables")
	}

	r.runables = append(r.runables, f)
}

// Run the runable functions and collect the errors
func (r *Runables) Run(ctx context.Context, maxConcurrentNum int) error {
	err := func() error {
		r.mu.Lock()
		defer r.mu.Unlock()

		if r.start {
			return fmt.Errorf("runables has been start")
		}

		r.start = true
		return nil
	}()
	if err != nil {
		return err
	}

	wg := NewGroup(maxConcurrentNum)
	ctx, cancel := context.WithCancel(ctx)

	for item := range r.runables {
		runable := r.runables[item]
		wg.Go(func() error { return runable(ctx) })
	}

	// close on a goroutine failed or all goroutine done
	err = wg.WaitAnyError()
	cancel()
	if err != nil {
		// wait for other goroutines return
		_ = wg.WaitResult()
		return err
	}

	return nil
}
