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
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/everoute/everoute/pkg/utils/sync"
)

func TestRunables(t *testing.T) {
	t.Run("should start all runables when run", func(t *testing.T) {
		RegisterTestingT(t)

		var runables sync.Runables
		var numbers = sets.NewInt()

		for i := 0; i < 10; i++ {
			i := i
			runables.Push(func(context.Context) error { numbers.Insert(i); return nil })
		}

		Expect(runables.Run(context.Background(), 1)).ShouldNot(HaveOccurred())
		Expect(numbers.List()).Should(HaveLen(10))
		Expect(numbers.List()).Should(ConsistOf([]int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}))
	})

	t.Run("should stop all runables after one failed", func(t *testing.T) {
		RegisterTestingT(t)

		var runables sync.Runables
		var doneCount int64

		for i := 0; i < 10; i++ {
			i := i
			runables.Push(func(ctx context.Context) error {
				if i == 5 {
					return errors.New("some error")
				}
				time.Sleep(time.Second)
				if ctx.Err() != nil {
					atomic.AddInt64(&doneCount, 1)
					return ctx.Err()
				}
				return nil
			})
		}

		Expect(runables.Run(context.Background(), 0)).Should(HaveOccurred())
		Expect(doneCount).Should(Equal(int64(9)))
	})

	t.Run("should do nothing on a closed context", func(t *testing.T) {
		RegisterTestingT(t)

		var runables sync.Runables
		var doneCount int64

		for i := 0; i < 10; i++ {
			runables.Push(func(ctx context.Context) error {
				if ctx.Err() != nil {
					atomic.AddInt64(&doneCount, 1)
					return ctx.Err()
				}
				return nil
			})
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		Expect(runables.Run(ctx, 0)).Should(HaveOccurred())
		Expect(doneCount).Should(Equal(int64(10)))
	})

	t.Run("should not push runable after run", func(t *testing.T) {
		RegisterTestingT(t)

		var runables sync.Runables

		Expect(runables.Run(context.Background(), 0)).ShouldNot(HaveOccurred())

		defer func() { Expect(recover()).ShouldNot(BeNil()) }()
		runables.Push(func(context.Context) error { return nil })

	})

	t.Run("should not repeate run runables", func(t *testing.T) {
		RegisterTestingT(t)

		var runables sync.Runables

		Expect(runables.Run(context.Background(), 0)).ShouldNot(HaveOccurred())
		Expect(runables.Run(context.Background(), 0)).Should(HaveOccurred())

	})
}
