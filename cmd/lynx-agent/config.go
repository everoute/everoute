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
	"io/ioutil"
	"log"

	"github.com/contiv/ofnet"
	"gopkg.in/yaml.v2"
)

const agentConfigFilePath = "/var/lib/lynx/agentconfig.yaml"

type agentConfig struct {
	BridgeName   string     `yaml:"bridgeName"`
	DatapathName string     `yaml:"datapathName"`
	LocalIp      string     `yaml:"localIp"`
	RpcPort      uint16     `yaml:"rpcPort"`
	OvsCtlPort   uint16     `yaml:"ovsControllerPort"`
	UplinkInfo   UplinkInfo `yaml:"uplinkInfo"`
}

type UplinkInfo struct {
	UplinkPortType string `yaml:"uplinkPortType"`
	UplinkPortName string `yaml:"uplinkPortName"`
	Links          []Link `yaml:"links"`
}

type Link struct {
	LinkInterfaceName string `yaml:"linkInterfaceName"`
	OfPortNo          uint32 `yaml:"ofPortNo"`
}

func getAgentConfig() (*agentConfig, error) {
	var err error
	agentConfig := agentConfig{}

	configdata, err := ioutil.ReadFile(agentConfigFilePath)
	if err != nil {
		log.Fatalf("error %v when read agentConfigFile", err)
		return nil, err
	}

	err = yaml.Unmarshal(configdata, &agentConfig)
	if err != nil {
		log.Fatalf("error %v when Unmarshal agentConfig", err)
		return nil, err
	}

	return &agentConfig, nil
}

func initUplinkConfig(agentConfig *agentConfig) *ofnet.PortInfo {
	var port ofnet.PortInfo
	port = ofnet.PortInfo{
		Name:     agentConfig.UplinkInfo.UplinkPortName,
		Type:     agentConfig.UplinkInfo.UplinkPortType,
		MbrLinks: []*ofnet.LinkInfo{},
	}

	for _, link := range agentConfig.UplinkInfo.Links {
		linkInfo := ofnet.LinkInfo{
			Name:   link.LinkInterfaceName,
			OfPort: link.OfPortNo,
			Port:   &port,
		}
		port.MbrLinks = append(port.MbrLinks, &linkInfo)
	}

	return &port
}
