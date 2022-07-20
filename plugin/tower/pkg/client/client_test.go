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

package client_test

import (
	"os"
	"testing"

	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/rand"

	"github.com/everoute/everoute/plugin/tower/pkg/client"
	"github.com/everoute/everoute/plugin/tower/pkg/server/fake"
	"github.com/everoute/everoute/plugin/tower/pkg/server/fake/graph/model"
)

var (
	server *fake.Server
)

func TestMain(m *testing.M) {
	server = fake.NewServer(nil)
	server.Serve()

	os.Exit(m.Run())
}

func TestClient_Query(t *testing.T) {
	RegisterTestingT(t)
	// todo
}

func TestClient_Subscription(t *testing.T) {
	RegisterTestingT(t)
	// todo
}

func TestClient_Auth(t *testing.T) {
	RegisterTestingT(t)

	user := &model.User{
		Name:     rand.String(10),
		Password: rand.String(10),
		Source:   model.UserSourceLdap,
		Token:    rand.String(10),
	}
	server.TrackerFactory().User().CreateOrUpdate(user)

	towerClient := server.NewClient()
	towerClient.UserInfo = getUserInfo(user)

	Eventually(towerClient.Auth).Should(Equal(user.Token))
}

func getUserInfo(user *model.User) *client.UserInfo {
	return &client.UserInfo{
		Username: user.Name,
		Password: user.Password,
		Source:   string(user.Source),
	}
}
