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

package policy_test

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("PolicyController", func() {
	var ctx context.Context

	BeforeEach(func() {
		ctx = context.Background()
	})
	AfterEach(func() {
		server.TrackerFactory().ResetAll()
		err := crdClient.SecurityV1alpha1().SecurityPolicies(namespace).DeleteCollection(ctx,
			metav1.DeleteOptions{},
			metav1.ListOptions{},
		)
		Expect(err).Should(Succeed())
	})

	Describe("SecurityPolicy", func() {

	})

	Describe("IsolationPolicy", func() {

	})
})
