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

package informer_test

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	"github.com/everoute/everoute/plugin/tower/pkg/informer"
	"github.com/everoute/everoute/plugin/tower/pkg/schema"
	fakeserver "github.com/everoute/everoute/plugin/tower/pkg/server/fake"
	. "github.com/everoute/everoute/plugin/tower/pkg/utils/testing"
)

func TestWaitForTask(t *testing.T) {
	server := fakeserver.NewServer(nil)
	server.Serve()

	towerFactory := informer.NewSharedInformerFactory(server.NewClient(), 0)
	taskMonitor := informer.NewTaskMonitor(towerFactory)

	towerFactory.Start(make(chan struct{}))
	towerFactory.WaitForCacheSync(make(chan struct{}))

	t.Run("Should return immediately on task successed", func(t *testing.T) {
		RegisterTestingT(t)

		task := NewTask(schema.TaskStatusSuccessed)
		server.TrackerFactory().Task().CreateOrUpdate(task)

		outTask, err := taskMonitor.WaitForTask(context.Background(), task.ID)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(outTask).Should(Equal(task))
	})

	t.Run("Should return immediately on task failed", func(t *testing.T) {
		RegisterTestingT(t)

		task := NewTask(schema.TaskStatusFailed)
		server.TrackerFactory().Task().CreateOrUpdate(task)

		outTask, err := taskMonitor.WaitForTask(context.Background(), task.ID)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(outTask).Should(Equal(task))
	})

	t.Run("Should wait for task complete", func(t *testing.T) {
		RegisterTestingT(t)

		task := NewTask(schema.TaskStatusPending)
		server.TrackerFactory().Task().CreateOrUpdate(task)

		go func() {
			task.Status = schema.TaskStatusSuccessed
			time.Sleep(5 * time.Second)
			server.TrackerFactory().Task().CreateOrUpdate(task)
		}()

		outTask, err := taskMonitor.WaitForTask(context.Background(), task.ID)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(outTask).Should(Equal(task))
	})
}
