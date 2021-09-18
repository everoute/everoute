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

package main

import (
	"fmt"
	"io/ioutil"

	"gopkg.in/yaml.v2"

	"github.com/smartxworks/lynx/pkg/agent/datapath"
)

const agentConfigFilePath = "/var/lib/lynx/agentconfig.yaml"

type agentConfig struct {
	DatapathConfig map[string]string `yaml:"datapathConfig"`
}

func getAgentConfig() (*agentConfig, error) {
	var err error
	agentConfig := agentConfig{}

	configdata, err := ioutil.ReadFile(agentConfigFilePath)
	if err != nil {
		return nil, fmt.Errorf("Failed to read agentConfig, error: %v. ", err)
	}

	err = yaml.Unmarshal(configdata, &agentConfig)
	if err != nil {
		return nil, fmt.Errorf("Failed to Unmarshal agentConfig, error: %v. ", err)
	}

	return &agentConfig, nil
}

func getDatapathConfig() (*datapath.Config, error) {
	agentConfig, err := getAgentConfig()
	if err != nil {
		return nil, fmt.Errorf("Failed to get agentConfig, error: %v. ", err)
	}

	dpConfig := new(datapath.Config)
	managedVDSMap := make(map[string]string)
	for managedvds, ovsbrname := range agentConfig.DatapathConfig {
		managedVDSMap[managedvds] = ovsbrname
	}
	dpConfig.ManagedVDSMap = managedVDSMap

	return dpConfig, nil
}
