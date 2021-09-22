/*
Copyright 2021 The Everoute Authors.

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

package matcher

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ContainsFlow", func() {

	When("passed a supported type", func() {
		var actualFlows map[string][]string
		var expectedFlows []string

		When("contains expected flows", func() {
			BeforeEach(func() {
				flow1 := "table=0, priority=103,arp,in_port=10 actions=goto_table:46"
				flow2 := "table=0, priority=100,ip actions=goto_table:5"
				flow3 := "table=0, priority=102,arp actions=CONTROLLER:65535"

				expectedFlows = []string{flow1, flow2}
				actualFlows = map[string][]string{
					"host01": {flow1, flow2, flow3},
					"host02": {flow1, flow2},
				}
			})

			It("should do the right thing", func() {
				Expect(actualFlows).Should(ContainsFlow(expectedFlows))
			})
		})

		When("not all contains expected flows", func() {
			BeforeEach(func() {
				flow1 := "table=0, priority=103,arp,in_port=10 actions=goto_table:46"
				flow2 := "table=0, priority=100,ip actions=goto_table:5"
				flow3 := "table=0, priority=102,arp actions=CONTROLLER:65535"

				expectedFlows = []string{flow1, flow2}
				actualFlows = map[string][]string{
					"host01": {flow1, flow2, flow3},
					"host02": {flow1, flow2},
					"host03": {flow1, flow3},
				}
			})

			It("should do the right thing", func() {
				Expect(actualFlows).ShouldNot(ContainsFlow(expectedFlows))
			})
		})
	})

	When("passed an unsupported type", func() {
		It("should error", func() {
			success, err := ContainsFlow(nil).Match("")
			Expect(success).Should(BeFalse())
			Expect(err).Should(HaveOccurred())

			success, err = ContainsFlow(nil).Match(0)
			Expect(success).Should(BeFalse())
			Expect(err).Should(HaveOccurred())
		})
	})
})
