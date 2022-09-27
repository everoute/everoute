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

package schema

import (
	"fmt"
	"reflect"

	"github.com/everoute/everoute/plugin/tower/pkg/utils"
)

type Task struct {
	ObjectMeta

	Description  string     `json:"description"`
	ErrorCode    *string    `json:"error_code"`
	ErrorMessage *string    `json:"error_message"`
	Internal     bool       `json:"internal"`
	Progress     float64    `json:"progress"`
	Snapshot     string     `json:"snapshot"`
	Status       TaskStatus `json:"status"`
}

func (t *Task) GetQueryRequest(skipFields map[string][]string) string {
	queryFields := utils.GqlTypeMarshal(reflect.TypeOf(t), skipFields, true)
	// only list latest 30 tasks
	return fmt.Sprintf("query {tasks(last: 20, orderBy: local_created_at_ASC) %s}", queryFields)
}

type TaskStatus string

const (
	TaskStatusExecuting TaskStatus = "EXECUTING"
	TaskStatusFailed    TaskStatus = "FAILED"
	TaskStatusPending   TaskStatus = "PENDING"
	TaskStatusSuccessed TaskStatus = "SUCCESSED"
)
