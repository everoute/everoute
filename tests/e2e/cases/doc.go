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

// Package cases contain e2e cases for verification lynx security function.
// Cases consist of different scenarios, a scenario usually like:
//
// Context("A basic test scenario", func() {
//   BeforeEach("Create needed endpoints and groups")
//   When("Creating policies for some purpose", func() {
//     BeforeEach("Create needed policies")
//     It("Check flows on agent, and verify reachable between endpoints")
//     When("Verify special cases, e.g. migrate, renew ip, update labels")
//   })
// })
package cases
