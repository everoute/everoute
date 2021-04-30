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
	"time"

	"gopkg.in/yaml.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/smartxworks/lynx/plugin/tower/pkg/client"
)

type Options struct {
	KubeConfig *rest.Config
	Config     *Config
}

type Config struct {
	Client     *client.Client        `yaml:"client"`
	Election   *LeaderElectionConfig `yaml:"election"`
	Controller *ControllerConfig     `yaml:"controller"`
}

type LeaderElectionConfig struct {
	Enable        bool          `yaml:"enable"`
	Name          string        `yaml:"name"`
	Namespace     string        `yaml:"namespace"`
	LeaseDuration time.Duration `yaml:"lease_duration"`
	RenewDeadline time.Duration `yaml:"renew_deadline"`
	RetryPeriod   time.Duration `yaml:"retry_period"`
}

type ControllerConfig struct {
	Resync  time.Duration `yaml:"resync"`
	Workers uint          `yaml:"workers"`
}

func (o *Options) LoadFromFile(kubeconfig string, configfile string) error {
	var err error
	o.setDefault()

	o.KubeConfig, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return err
	}

	data, err := ioutil.ReadFile(configfile)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(data, o.Config)
	if err != nil {
		return err
	}

	return nil
}

func (o *Options) setDefault() {
	if o.Config == nil {
		o.Config = &Config{}
	}

	if o.Config.Election == nil {
		o.Config.Election = &LeaderElectionConfig{
			Enable:        true,
			Name:          "lynx.plugin.tower.election",
			Namespace:     metav1.NamespaceDefault,
			LeaseDuration: 60 * time.Second,
			RenewDeadline: 15 * time.Second,
			RetryPeriod:   5 * time.Second,
		}
	}

	if o.Config.Controller == nil {
		o.Config.Controller = &ControllerConfig{
			Resync:  0,
			Workers: 10,
		}
	}
}
