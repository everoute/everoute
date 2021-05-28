/*
Copyright 2021 The Lynx Authors.

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

package node

import (
	"fmt"
)

type Controller struct {
	*Node
}

const (
	controllerBinaryName = "lynx-controller"
)

func (n *Controller) Restart() error {
	return n.reRunProcess(controllerBinaryName)
}

func (n *Controller) GetName() string {
	return fmt.Sprintf("%s/%s", n.Name, controllerBinaryName)
}

func (n *Controller) FetchLog() ([]byte, error) {
	return n.fetchFile(fmt.Sprintf("/var/log/%s.log", controllerBinaryName))
}

func (n *Controller) Healthz() (bool, error) {
	return n.checkProcess(controllerBinaryName)
}
