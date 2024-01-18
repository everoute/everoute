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
	"sync"

	"k8s.io/apimachinery/pkg/util/errors"
)

// Group run multiple tasks concurrently, and collect the results
type Group struct {
	concurrentChan chan struct{}
	waitGroup      sync.WaitGroup

	errLock sync.Mutex
	errList []error
	errChan chan error // errChan store the first error
}

// NewGroup return an instance of Group
// concurrent won't limit when maxConcurrentNum is zero
func NewGroup(maxConcurrentNum int) *Group {
	var group = &Group{
		errChan: make(chan error, 1),
	}
	if maxConcurrentNum > 0 {
		group.concurrentChan = make(chan struct{}, maxConcurrentNum)
	}
	return group
}

// Go start a new task
func (g *Group) Go(fn func() error) {
	g.waitGroup.Add(1)

	go func() {
		defer g.waitGroup.Done()

		if g.concurrentChan != nil {
			g.concurrentChan <- struct{}{}
			defer func() {
				<-g.concurrentChan
			}()
		}

		if err := fn(); err != nil {
			// store the first error into error chan
			select {
			case g.errChan <- err:
			default:
			}

			g.errLock.Lock()
			g.errList = append(g.errList, err)
			g.errLock.Unlock()
		}
	}()
}

// WaitResult wait for tasks done, and return the result
func (g *Group) WaitResult() error {
	g.waitGroup.Wait()
	return errors.NewAggregate(g.errList)
}

// WaitAnyError return immediately on one goroutine return error
// or wait unit task done
func (g *Group) WaitAnyError() error {
	done := make(chan struct{})

	go func() {
		g.waitGroup.Wait()
		close(done)
	}()

	select {
	case <-done:
		return errors.NewAggregate(g.errList)
	case err := <-g.errChan:
		return err
	}
}
