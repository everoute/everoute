package overlay

import (
	"math/rand"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/everoute/everoute/pkg/types"
)

func TestEndpointIPsEqual(t *testing.T) {
	tests := []struct {
		name string
		news []types.IPAddress
		olds []types.IPAddress
		exp  bool
	}{
		{
			name: "no ip",
			olds: nil,
			news: []types.IPAddress{},
			exp:  true,
		},
		{
			name: "add ip",
			news: []types.IPAddress{types.IPAddress("1.1.1.1")},
			olds: nil,
			exp:  false,
		},
		{
			name: "update ip",
			news: []types.IPAddress{types.IPAddress("1.1.1.1")},
			olds: []types.IPAddress{types.IPAddress("1.1.1.3")},
			exp:  false,
		},
		{
			name: "del ip",
			news: []types.IPAddress{},
			olds: []types.IPAddress{types.IPAddress("1.1.1.3")},
			exp:  false,
		},
	}

	for i := range tests {
		res := endpointIPsEqual(tests[i].news, tests[i].olds)
		if res != tests[i].exp {
			t.Errorf("test %s failed, the expect value is %v, real is %v", tests[i].name, tests[i].exp, res)
		}
	}
}


func TestEndpointAgentsEqual(t *testing.T) {
	tests := []struct {
		name string
		news []string
		olds []string
		exp  bool
	}{
		{
			name: "no agent",
			olds: nil,
			news: []string{},
			exp:  true,
		},
		{
			name: "add agent",
			news: []string{"node01"},
			olds: nil,
			exp:  false,
		},
		{
			name: "update agent",
			news: []string{"node01"},
			olds: []string{"node02"},
			exp:  false,
		},
		{
			name: "del agent",
			news: []string{},
			olds: []string{"node01"},
			exp:  false,
		},
		{
			name: "no update",
			news: []string{"node03", "node01"},
			olds: []string{"node01", "node03"},
			exp:  true,
		},
	}

	for i := range tests {
		res := endpointAgentsEqual(tests[i].news, tests[i].olds)
		if res != tests[i].exp {
			t.Errorf("test %s failed, the expect value is %v, real is %v", tests[i].name, tests[i].exp, res)
		}
	}
}

func TestNodePredicate(t *testing.T) {
	localNode := "node01"
	predicateFuncs := nodePredicate(localNode)

	// create func
	createTests := []struct{
		name string
		node string
		internalIP string
		exp bool
	}{
		{
			name: "accept event",
			node: "node02",
			internalIP: "10.10.1.1",
			exp: true,
		},
		{
			name: "local node",
			node: localNode,
			internalIP: "10.10.1.1",
			exp: false,
		},
		{
			name: "node without internal ip",
			node: "node02",
			exp: false,
		},
	}
	for _, curT := range createTests {
		obj := setupNodeEvent(curT.node, curT.internalIP)
		e := event.CreateEvent{
			Object: obj,
		}
		res := predicateFuncs.Create(e)
		if res != curT.exp {
			t.Errorf("nodePredicate.Create test %s faild, expect is %v, real is %v", curT.name, curT.exp, res)
		}
	}

	// update func
	updateTests := []struct{
		name string
		node string
		oldIP string
		newIP string
		exp bool
	}{
		{
			name: "internal ip doesn't update",
			node: "node02",
			oldIP: "10.10.2.3",
			newIP: "10.10.2.3",
			exp: false,
		},
		{
			name: "local node",
			node: localNode,
			oldIP: "10.10.2.3",
			newIP: "10.10.2.4",
			exp: false,
		},
		{
			name: "event accept",
			node: "node02",
			oldIP: "10.10.2.3",
			newIP: "10.10.2.4",
			exp: true,
		},
	}
	for _, curT := range updateTests {
		t.Logf("---- curT: %v", curT)
		oldObj := setupNodeEvent(curT.node, curT.oldIP)
		newObj := setupNodeEvent(curT.node, curT.newIP)
		e := event.UpdateEvent{
			ObjectOld: oldObj,
			ObjectNew: newObj,
		}
		t.Logf("---- event: %v", e)
		res := predicateFuncs.Update(e)
		if res != curT.exp {
			t.Errorf("nodePredicate.Update test %s faild, expect is %v, real is %v", curT.name, curT.exp, res)
		} 
	}

	// delete func
	deleteTests := []struct{
		name string
		node string
		exp bool
	}{
		{
			name: "accept event",
			node: "node02",
			exp: true,
		},
		{
			name: "local node",
			node: localNode,
			exp: false,
		},
	}
	for _, curT := range deleteTests {
		obj := setupNodeEvent(curT.node, "")
		e := event.DeleteEvent{
			Object: obj,
		}
		res := predicateFuncs.Delete(e)
		if res != curT.exp {
			t.Errorf("nodePredicate.Delete test %s faild, expect is %v, real is %v", curT.name, curT.exp, res)
		} 
	}
}

func setupNodeEvent(node, ip string) *corev1.Node {
	meta := metav1.ObjectMeta{
		Name: node,
	}

	obj := &corev1.Node{ObjectMeta: meta}
	rand.Seed(time.Now().UnixNano())
	obj.Status.Addresses = make([]corev1.NodeAddress, 0)
	if rand.Intn(2) == 1 {
		obj.Status.Addresses = append(obj.Status.Addresses, corev1.NodeAddress{
			Type: corev1.NodeExternalIP,
			Address: "13.13.12.1",
		})
	}
	if ip != "" {
		obj.Status.Addresses = append(obj.Status.Addresses, corev1.NodeAddress{
			Type: corev1.NodeInternalIP,
			Address: ip,
		})
	}

	return obj
}