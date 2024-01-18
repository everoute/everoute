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

package sync_test

import (
	goerr "errors"
	gosync "sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/rand"

	"github.com/everoute/everoute/pkg/utils/sync"
)

func TestGroup(t *testing.T) {
	t.Run("start group without max goroutines limit", func(t *testing.T) {
		RegisterTestingT(t)
		var generator goroutineGenerator
		var group = sync.NewGroup(0)
		for i := 0; i < 5; i++ {
			group.Go(generator.newGoroutineFunc(nil))
		}
		Expect(group.WaitResult()).ShouldNot(HaveOccurred())
		Expect(generator.data).Should(Equal([]int{0, 0, 0, 0, 0, 1, 1, 1, 1, 1}))
	})

	t.Run("start group with serial goroutines", func(t *testing.T) {
		RegisterTestingT(t)
		var generator goroutineGenerator
		var group = sync.NewGroup(1)
		for i := 0; i < 5; i++ {
			group.Go(generator.newGoroutineFunc(nil))
		}
		Expect(group.WaitResult()).ShouldNot(HaveOccurred())
		Expect(generator.data).Should(Equal([]int{0, 1, 0, 1, 0, 1, 0, 1, 0, 1}))
	})

	t.Run("start group with max goroutines limit", func(t *testing.T) {
		RegisterTestingT(t)
		var generator goroutineGenerator
		var group = sync.NewGroup(2)
		for i := 0; i < 5; i++ {
			group.Go(generator.newGoroutineFunc(nil))
		}
		Expect(group.WaitResult()).ShouldNot(HaveOccurred())
		Expect(generator.data).Should(Equal([]int{0, 0, 1, 0, 1, 0, 1, 0, 1, 1}))
	})

	t.Run("start group with goroutines return error", func(t *testing.T) {
		RegisterTestingT(t)
		var generator goroutineGenerator
		var group = sync.NewGroup(0)
		var err = goerr.New("some error")
		for i := 0; i < 5; i++ {
			if i == 2 {
				group.Go(generator.newGoroutineFunc(err))
			} else {
				group.Go(generator.newGoroutineFunc(nil))
			}
		}

		Expect(goerr.Is(group.WaitResult(), err)).Should(BeTrue())
		Expect(generator.data).Should(Equal([]int{0, 0, 0, 0, 0, 1, 1, 1, 1, 1}))
	})

	t.Run("should return immediately on any error", func(t *testing.T) {
		RegisterTestingT(t)
		var group = sync.NewGroup(0)
		var err = goerr.New("same error")

		group.Go(func() error { return err })
		group.Go(func() error { select {} })

		Expect(group.WaitAnyError()).Should(HaveOccurred())
	})
}

type goroutineGenerator struct {
	mutex gosync.Mutex
	data  []int
}

func (g *goroutineGenerator) newGoroutineFunc(err error) func() error {
	var push = func(i int) {
		g.mutex.Lock()
		g.data = append(g.data, i)
		g.mutex.Unlock()
	}
	return func() error {
		push(0)
		time.Sleep(time.Duration(rand.Int63nRange(1000, 1200)) * time.Millisecond)
		push(1)
		return err
	}
}
