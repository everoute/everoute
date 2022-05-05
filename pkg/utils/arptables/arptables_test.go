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

package arptables

import (
	"reflect"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestArptables(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Arptables Test Suite")
}

var _ = Describe("Test arptables.go", func() {
	BeforeSuite(func() {
		_ = Flush("INPUT")
	})
	AfterEach(func() {
		_ = Flush("INPUT")
	})

	It("Test List and Flush", func() {
		_ = run("-A", "INPUT", "-t", "filter", "-j", "ACCEPT")
		_ = run("-A", "INPUT", "-t", "filter", "-j", "DROP", "-i", "eth0", "--source-mac",
			"aa:aa:aa:aa:aa:aa", "-d", "!", "100.100.100.100")

		rules, err := List("INPUT", "filter")
		Expect(err).Should(BeNil())
		Expect(len(rules)).Should(Equal(2))
		rule1 := &ArpRule{Target: "ACCEPT"}
		rule2 := &ArpRule{
			Target:  "DROP",
			InIface: "eth0",
			SrcMac:  "aa:aa:aa:aa:aa:aa",
			DstIP:   "! 100.100.100.100",
		}
		Expect(RuleContain(rules, rule1)).Should(BeTrue())
		Expect(RuleContain(rules, rule2)).Should(BeTrue())

		_ = Flush("INPUT")
		rules, err = List("INPUT", "filter")
		Expect(err).Should(BeNil())
		Expect(len(rules)).Should(Equal(0))
	})

	It("Test Append", func() {
		_ = Append("INPUT", "filter", "-j", "DROP", "-i", "eth0", "--source-mac",
			"aa:aa:aa:aa:aa:aa", "-d", "!", "100.100.100.100")

		rules, err := List("INPUT", "filter")
		Expect(err).Should(BeNil())
		Expect(len(rules)).Should(Equal(1))
		rule := &ArpRule{
			Target:  "DROP",
			InIface: "eth0",
			SrcMac:  "aa:aa:aa:aa:aa:aa",
			DstIP:   "! 100.100.100.100",
		}
		Expect(RuleContain(rules, rule)).Should(BeTrue())

		err = AppendUnique("INPUT", "filter", rule)

		Expect(err).ShouldNot(BeNil())
		rules, err = List("INPUT", "filter")
		Expect(err).Should(BeNil())
		Expect(len(rules)).Should(Equal(1))
	})

	It("Test Insert", func() {
		_ = Insert("INPUT", "filter", 1, "-j", "DROP", "-i", "eth0", "--source-mac",
			"aa:aa:aa:aa:aa:aa", "-d", "!", "100.100.100.100")

		rules, err := List("INPUT", "filter")
		Expect(err).Should(BeNil())
		Expect(len(rules)).Should(Equal(1))
		rule := &ArpRule{
			Target:  "DROP",
			InIface: "eth0",
			SrcMac:  "aa:aa:aa:aa:aa:aa",
			DstIP:   "! 100.100.100.100",
		}
		Expect(RuleContain(rules, rule)).Should(BeTrue())

		err = InsertUnique("INPUT", "filter", 1, rule)
		Expect(err).ShouldNot(BeNil())
		rules, err = List("INPUT", "filter")
		Expect(err).Should(BeNil())
		Expect(len(rules)).Should(Equal(1))
	})

	It("Test Delete", func() {
		_ = Insert("INPUT", "filter", 1, "-j", "DROP", "-i", "eth0", "--source-mac",
			"aa:aa:aa:aa:aa:aa", "-d", "!", "100.100.100.100")
		_ = Insert("INPUT", "filter", 1, "-j", "DROP", "-i", "eth0", "--source-mac",
			"aa:aa:aa:aa:aa:aa", "-d", "!", "100.100.100.100")
		_ = Insert("INPUT", "filter", 1, "-j", "ACCEPT")

		rules, err := List("INPUT", "filter")
		Expect(err).Should(BeNil())
		Expect(len(rules)).Should(Equal(3))

		err = Delete("INPUT", "filter", "-j", "DROP", "-i", "eth0")
		Expect(err).ShouldNot(BeNil())

		_ = Delete("INPUT", "filter", "-j", "DROP", "-i", "eth0", "--source-mac",
			"aa:aa:aa:aa:aa:aa", "-d", "!", "100.100.100.100")

		rules, err = List("INPUT", "filter")
		Expect(err).Should(BeNil())
		Expect(len(rules)).Should(Equal(2))
	})

	It("Test DeleteAll", func() {
		_ = Insert("INPUT", "filter", 1, "-j", "DROP", "-i", "eth0", "--source-mac",
			"aa:aa:aa:aa:aa:aa", "-d", "!", "100.100.100.100")
		_ = Insert("INPUT", "filter", 1, "-j", "DROP", "-i", "eth0", "--source-mac",
			"aa:aa:aa:aa:aa:aa", "-d", "!", "100.100.100.100")

		rules, err := List("INPUT", "filter")
		Expect(err).Should(BeNil())
		Expect(len(rules)).Should(Equal(2))

		DeleteAll("INPUT", "filter", "-j", "DROP", "-i", "eth0", "--source-mac",
			"aa:aa:aa:aa:aa:aa", "-d", "!", "100.100.100.100")

		rules, err = List("INPUT", "filter")
		Expect(err).Should(BeNil())
		Expect(len(rules)).Should(Equal(0))
	})

})

func RuleContain(rules []*ArpRule, rule *ArpRule) bool {
	for _, item := range rules {
		if reflect.DeepEqual(item, rule) {
			return true
		}
	}
	return false
}
