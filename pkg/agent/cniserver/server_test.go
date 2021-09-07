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

package cniserver

import (
	"os"

	"github.com/containernetworking/cni/pkg/types"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	cnipb "github.com/smartxworks/lynx/pkg/apis/cni/v1alpha1"
)

var _ = Describe("Test cniserver", func() {
	s := &CNIServer{}
	It("Test Parse Conf", func() {
		request := &cnipb.CniRequest{
			ContainerId: "containerid",
			Netns:       "ns",
			Ifname:      "ifname",
			Args:        "K8S_POD_NAME=123;K8S_POD_NAMESPACE=456;K8S_POD_INFRA_CONTAINER_ID=789",
			Path:        "path",
			Stdin: []byte("{\n  \"cniVersion\": \"1.0.0\",\n  \"name\": \"test\",\n  \"plugins\": [\n    {\n      " +
				"\"type\": \"bridge\",\n      // plugin specific parameters\n      \"bridge\": \"cni0\",\n      " +
				"\"keyA\": [\"some more\", \"plugin specific\", \"configuration\"],\n      \n      \"ipam\": {\n      " +
				"  \"type\": \"host-local\",\n        // ipam specific\n        \"subnet\": \"10.1.0.0/16\",\n       " +
				" \"gateway\": \"10.1.0.1\",\n        \"routes\": [\n            {\"dst\": \"0.0.0.0/0\"}\n        ]\n " +
				"     },\n      \"dns\": {\n        \"nameservers\": [ \"10.1.0.1\" ]\n      }\n    },\n    {\n     " +
				" \"type\": \"tuning\",\n      \"capabilities\": {\n        \"mac\": true\n      },\n     " +
				" \"sysctl\": {\n        \"net.core.somaxconn\": \"500\"\n      }\n    },\n    {\n        " +
				"\"type\": \"portmap\",\n        \"capabilities\": {\"portMappings\": true}\n    }\n  ]\n}\n"),
		}
		conf, args, err := s.ParseConf(request)
		Expect(err).Should(Succeed())
		Expect(conf.CNIVersion).Should(Equal("1.0.0"))
		Expect(args.K8S_POD_NAMESPACE).Should(Equal("123"))
	})
	It("Test Parse Result", func() {
		result := &cniv1.Result{
			CNIVersion: "",
			Interfaces: nil,
			IPs:        nil,
			Routes:     nil,
			DNS:        types.DNS{},
		}
		_, err := s.ParseResult(result)
		Expect(err).Should(Succeed())
	})
	It("Test SetEnv", func() {
		req := &cnipb.CniRequest{
			ContainerId: "11",
			Netns:       "22",
			Ifname:      "33",
			Path:        "44",
		}
		SetEnv(req)
		Expect(os.Getenv("CNI_CONTAINERID")).Should(Equal(11))
		Expect(os.Getenv("CNI_NETNS")).Should(Equal(22))
		Expect(os.Getenv("CNI_IFNAME")).Should(Equal(33))
		Expect(os.Getenv("CNI_PATH")).Should(Equal(44))
	})
	It("Test SetEnv", func() {
		req := &cnipb.CniRequest{
			ContainerId: "11",
			Netns:       "22",
			Ifname:      "33",
			Path:        "44",
		}
		SetEnv(req)
		Expect(os.Getenv("CNI_CONTAINERID")).Should(Equal(11))
		Expect(os.Getenv("CNI_NETNS")).Should(Equal(22))
		Expect(os.Getenv("CNI_IFNAME")).Should(Equal(33))
		Expect(os.Getenv("CNI_PATH")).Should(Equal(44))
	})
})
