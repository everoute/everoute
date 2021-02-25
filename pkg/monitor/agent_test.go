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

package monitor

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey"
	ovsdb "github.com/contiv/libovsdb"
	. "github.com/onsi/gomega"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	agentv1alpha1 "github.com/smartxworks/lynx/pkg/apis/agent/v1alpha1"
	"github.com/smartxworks/lynx/pkg/client/clientset_generated/clientset/scheme"
)

const (
	timeout  = time.Second * 10
	interval = time.Millisecond * 250
)

var (
	k8sClient client.Client
	ovsClient *ovsdb.OvsdbClient
	agentName string
)

func TestMain(m *testing.M) {
	k8sClient = fake.NewFakeClientWithScheme(scheme.Scheme)

	// return new random agentname instead of read/write from file
	gomonkey.ApplyFunc(readOrGenerateAgentName, func() (string, error) {
		return string(uuid.NewUUID()), nil
	})

	agentMonitor, err := NewAgentMonitor(k8sClient)
	if err != nil {
		klog.Fatal(err)
	}
	ovsClient = agentMonitor.ovsClient
	agentName = agentMonitor.Name()

	go agentMonitor.Run(ctrl.SetupSignalHandler())

	m.Run()
}

func TestAgentMonitor(t *testing.T) {
	RegisterTestingT(t)

	brName := string(uuid.NewUUID())
	portName := string(uuid.NewUUID())
	externalIDs := map[string]string{"lynx.agent.monitor.externalID.name": "lynx.agent.monitor.externalID.value"}

	t.Logf("create new bridge %s", brName)
	Expect(createBridge(ovsClient, brName)).Should(Succeed())

	t.Run("monitor should create new bridge", func(t *testing.T) {
		Eventually(func() error {
			_, err := getBridge(k8sClient, brName)
			return err
		}, timeout, interval).Should(Succeed())
	})

	t.Logf("create new port %s", portName)
	Expect(createPort(ovsClient, brName, portName)).Should(Succeed())

	t.Run("monitor should create new port", func(t *testing.T) {
		Eventually(func() error {
			_, err := getPort(k8sClient, brName, portName)
			return err
		}, timeout, interval).Should(Succeed())
	})

	t.Logf("update port %s externalIDs to %+v", portName, externalIDs)
	Expect(updatePort(ovsClient, portName, externalIDs)).Should(Succeed())

	t.Run("monitor should update port externalID", func(t *testing.T) {
		Eventually(func() map[string]string {
			port, _ := getPort(k8sClient, brName, portName)
			return port.ExternalIDs
		}, timeout, interval).Should(Equal(externalIDs))
	})

	t.Logf("delete port %s on bridge %s", portName, brName)
	Expect(deletePort(ovsClient, brName, portName)).Should(Succeed())

	t.Run("monitor should delete port", func(t *testing.T) {
		Eventually(func() bool {
			_, err := getPort(k8sClient, brName, portName)
			return isNotFoundError(err)
		}, timeout, interval).Should(BeTrue())
	})

	t.Logf("delete bridge %s", brName)
	Expect(deleteBridge(ovsClient, brName)).Should(Succeed())

	t.Run("monitor should delete bridge", func(t *testing.T) {
		Eventually(func() bool {
			_, err := getBridge(k8sClient, brName)
			return isNotFoundError(err)
		}, timeout, interval).Should(BeTrue())
	})
}

const emptyUUID = "00000000-0000-0000-0000-000000000000"

func createBridge(client *ovsdb.OvsdbClient, brName string) error {
	bridgeOperation := ovsdb.Operation{
		Op:       "insert",
		Table:    "Bridge",
		UUIDName: "dummy",
		Row: map[string]interface{}{
			"name": brName,
		},
	}

	mutateOperation := ovsdb.Operation{
		Op:        "mutate",
		Table:     "Open_vSwitch",
		Mutations: []interface{}{[]interface{}{"bridges", "insert", ovsdb.UUID{GoUuid: "dummy"}}},
		Where:     []interface{}{[]interface{}{"_uuid", "excludes", ovsdb.UUID{GoUuid: emptyUUID}}},
	}

	_, err := ovsdbTransact(client, "Open_vSwitch", bridgeOperation, mutateOperation)
	return err
}

func deleteBridge(client *ovsdb.OvsdbClient, brName string) error {
	brUUID, err := getMemberUUID(client, "Bridge", brName)
	if err != nil {
		return fmt.Errorf("can't found uuid of bridge %s: %s", brName, err)
	}

	bridgeOperation := ovsdb.Operation{
		Op:    "delete",
		Table: "Bridge",
		Where: []interface{}{[]interface{}{"name", "==", brName}},
	}

	mutateOperation := ovsdb.Operation{
		Op:        "mutate",
		Table:     "Open_vSwitch",
		Mutations: []interface{}{[]interface{}{"bridges", "delete", brUUID}},
		Where:     []interface{}{[]interface{}{"_uuid", "excludes", ovsdb.UUID{GoUuid: emptyUUID}}},
	}

	_, err = ovsdbTransact(client, "Open_vSwitch", bridgeOperation, mutateOperation)
	return err
}

// createPort also create an interface with the same name
func createPort(client *ovsdb.OvsdbClient, brName, portName string) error {
	ifaceOperation := ovsdb.Operation{
		Op:    "insert",
		Table: "Interface",
		Row: map[string]interface{}{
			"name": portName,
		},
		UUIDName: "ifacedummy",
	}

	portOperation := ovsdb.Operation{
		Op:       "insert",
		Table:    "Port",
		UUIDName: "dummy",
		Row: map[string]interface{}{
			"name":       portName,
			"interfaces": ovsdb.UUID{GoUuid: "ifacedummy"},
		},
	}

	mutateOperation := ovsdb.Operation{
		Op:        "mutate",
		Table:     "Bridge",
		Mutations: []interface{}{[]interface{}{"ports", "insert", ovsdb.UUID{GoUuid: "dummy"}}},
		Where:     []interface{}{[]interface{}{"name", "==", brName}},
	}

	_, err := ovsdbTransact(client, "Open_vSwitch", ifaceOperation, portOperation, mutateOperation)
	return err
}

func updatePort(client *ovsdb.OvsdbClient, portName string, externalIDs map[string]string) error {
	if externalIDs == nil {
		externalIDs = make(map[string]string)
	}
	ovsExternalIDs, _ := ovsdb.NewOvsMap(externalIDs)

	portOperation := ovsdb.Operation{
		Op:    "update",
		Table: "Port",
		Row: map[string]interface{}{
			"external_ids": ovsExternalIDs,
		},
		Where: []interface{}{[]interface{}{"name", "==", portName}},
	}

	_, err := ovsdbTransact(client, "Open_vSwitch", portOperation)
	return err
}

func deletePort(client *ovsdb.OvsdbClient, brName, portName string) error {
	portUUID, err := getMemberUUID(client, "Port", portName)
	if err != nil {
		return fmt.Errorf("can't found uuid of port %s: %s", portName, err)
	}

	ifaceOperation := ovsdb.Operation{
		Op:    "delete",
		Table: "Interface",
		Where: []interface{}{[]interface{}{"name", "==", portName}},
	}

	portOperation := ovsdb.Operation{
		Op:    "delete",
		Table: "Port",
		Where: []interface{}{[]interface{}{"name", "==", portName}},
	}

	mutateOperation := ovsdb.Operation{
		Op:        "mutate",
		Table:     "Bridge",
		Mutations: []interface{}{[]interface{}{"ports", "delete", portUUID}},
		Where:     []interface{}{[]interface{}{"name", "==", brName}},
	}

	_, err = ovsdbTransact(client, "Open_vSwitch", ifaceOperation, portOperation, mutateOperation)
	return err
}

func getMemberUUID(client *ovsdb.OvsdbClient, tableName, memberName string) (ovsdb.UUID, error) {
	selectOperation := ovsdb.Operation{
		Op:    "select",
		Table: tableName,
		Where: []interface{}{[]interface{}{"name", "==", memberName}},
	}

	result, err := ovsdbTransact(client, "Open_vSwitch", selectOperation)
	if err != nil {
		return ovsdb.UUID{}, err
	}

	if len(result[0].Rows) == 0 {
		return ovsdb.UUID{}, fmt.Errorf("no member name with %s found in table %s", memberName, tableName)
	}

	return ovsdb.UUID{
		GoUuid: result[0].Rows[0]["_uuid"].([]interface{})[1].(string),
	}, nil
}

func ovsdbTransact(client *ovsdb.OvsdbClient, database string, operation ...ovsdb.Operation) ([]ovsdb.OperationResult, error) {
	results, err := client.Transact(database, operation...)
	for item, result := range results {
		if result.Error != "" {
			return results, fmt.Errorf("operator %d: %s", item, result.Error)
		}
	}

	return results, err
}

func getBridge(client client.Client, brName string) (*agentv1alpha1.OVSBridge, error) {
	agentInfo := &agentv1alpha1.AgentInfo{}
	err := client.Get(context.Background(), k8stypes.NamespacedName{Name: agentName}, agentInfo)
	if err != nil {
		return nil, err
	}

	for _, bridge := range agentInfo.OVSInfo.Bridges {
		if bridge.Name == brName {
			return &bridge, nil
		}
	}

	return nil, notFoundError(fmt.Errorf("bridge %s not found in agentInfo", brName))
}

func getPort(client client.Client, brName, portName string) (*agentv1alpha1.OVSPort, error) {
	bridge, err := getBridge(client, brName)
	if err != nil {
		return nil, err
	}

	for _, port := range bridge.Ports {
		if port.Name == portName {
			return &port, nil
		}
	}

	return nil, notFoundError(fmt.Errorf("port %s not found in agentInfo", portName))
}

type notFoundError error

func isNotFoundError(err error) bool {
	switch err.(type) {
	case notFoundError:
		return true
	default:
		return false
	}
}
