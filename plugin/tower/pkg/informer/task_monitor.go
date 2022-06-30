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

package informer

import (
	"context"
	"fmt"
	"sync"

	"k8s.io/client-go/tools/cache"

	"github.com/everoute/everoute/plugin/tower/pkg/client"
	"github.com/everoute/everoute/plugin/tower/pkg/schema"
)

type taskMonitor struct {
	cond *sync.Cond

	taskInformer       cache.SharedIndexInformer
	taskLister         Lister
	taskInformerSynced cache.InformerSynced
}

func NewTaskMonitor(towerFactory SharedInformerFactory) client.TaskMonitor {
	taskInformer := towerFactory.Task()

	t := &taskMonitor{
		cond:               sync.NewCond(&sync.Mutex{}),
		taskInformer:       taskInformer,
		taskLister:         taskInformer.GetIndexer(),
		taskInformerSynced: taskInformer.HasSynced,
	}

	taskInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    t.addTask,
		UpdateFunc: t.updateTask,
	})

	return t
}

func (t *taskMonitor) WaitForTask(ctx context.Context, taskID string) (*schema.Task, error) {
	if !cache.WaitForCacheSync(make(chan struct{}), t.taskInformerSynced) {
		return nil, fmt.Errorf("error waiting for cache sync for task")
	}

	t.cond.L.Lock()
	defer t.cond.L.Unlock()
	for {
		result, ok, _ := t.taskLister.GetByKey(taskID)
		if ok {
			switch result.(*schema.Task).Status {
			case schema.TaskStatusFailed, schema.TaskStatusSuccessed:
				return result.(*schema.Task), nil
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			t.cond.Wait()
		}
	}
}

func (t *taskMonitor) addTask(new interface{}) {
	newTask := new.(*schema.Task)
	switch newTask.Status {
	case schema.TaskStatusFailed, schema.TaskStatusSuccessed:
		t.cond.Broadcast()
	}
}

func (t *taskMonitor) updateTask(old interface{}, new interface{}) {
	newTask := new.(*schema.Task)
	switch newTask.Status {
	case schema.TaskStatusFailed, schema.TaskStatusSuccessed:
		t.cond.Broadcast()
	}
}
