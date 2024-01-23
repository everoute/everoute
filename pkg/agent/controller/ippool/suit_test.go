package ippool

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/everoute/everoute/pkg/agent/datapath"
)

const (
	Interval = time.Second
	Timeout  = time.Minute
	BrName   = "ipam"
	Ns       = "test-ipam"

	pool1Gw     = "10.10.10.1"
	pool1Cidr   = "10.10.10.1/25"
	pool1Subnet = "10.10.10.0/24"

	gwIPPoolSubnet = "240.100.0.0/16"
)

var (
	r      *Reconciler
	stopCh context.Context
	cancel context.CancelFunc

	routeCtrl = newOverlayRoute()
	iptCtrl   = newOverlayIPtables()

	iptError   error = fmt.Errorf("iptables failed")
	routeError error = fmt.Errorf("route failed")
)

func TestController(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ippool Suite")
}

var _ = BeforeSuite(func() {
	Expect(datapath.ExcuteCommand(datapath.SetupBridgeChain, BrName)).ToNot(HaveOccurred())
	Expect(datapath.ExcuteCommand(datapath.SetupCNIBridgeChain, BrName)).ToNot(HaveOccurred())
	Expect(datapath.ExcuteCommand(datapath.SetupProxyBridgeChain, BrName)).ToNot(HaveOccurred())
	Expect(datapath.ExcuteCommand(datapath.SetupTunnelBridgeChain, BrName)).ToNot(HaveOccurred())

	stopCh, cancel = context.WithCancel(ctrl.SetupSignalHandler())

	dpMgr, err := datapath.InitCNIDpMgrUT(stopCh.Done(), BrName, true, true, true)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(dpMgr).ShouldNot(BeNil())

	r = &Reconciler{
		IptCtrl:   iptCtrl,
		RouteCtrl: routeCtrl,
		DpMgr:     dpMgr,
		gws:       make(map[string]sets.Set[types.NamespacedName]),
		subnets:   make(map[string]sets.Set[types.NamespacedName]),
	}

	go func() {
		defer GinkgoRecover()
	}()
}, 60)

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	// cancel()
	Expect(datapath.ExcuteCommand(datapath.CleanBridgeChain, BrName)).NotTo(HaveOccurred())
	Expect(datapath.ExcuteCommand(datapath.CleanProxyBridgeChain, BrName)).NotTo(HaveOccurred())
})

func excuteCommand(commandStr string) ([]byte, error) {
	out, err := exec.Command("/bin/sh", "-c", commandStr).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to excute cmd: %v, error: %v", string(out), err)
	}

	return out, nil
}

func dumpLocalBrIcmpReply() ([]string, error) {
	cmdStr := fmt.Sprintf("sudo /usr/bin/ovs-ofctl -O Openflow13 dump-flows %s table=30", BrName)
	flows, err := dumpflows(cmdStr)
	if err != nil {
		return nil, err
	}
	gws := []string{}
	for _, f := range flows {
		fmt.Println(f)
		if !strings.Contains(f, "icmp") {
			continue
		}
		fileds := strings.Split(f, ",")
		gw := strings.Split(fileds[3], "=")[1]
		gws = append(gws, gw)
	}
	return gws, nil
}

func dumpLocalBrArpProxy() ([]string, error) {
	cmdStr := fmt.Sprintf("sudo /usr/bin/ovs-ofctl -O Openflow13 dump-flows %s table=10", BrName)
	flows, err := dumpflows(cmdStr)
	if err != nil {
		return nil, err
	}
	subnets := []string{}
	for _, f := range flows {
		if !strings.Contains(f, "priority=200,arp") {
			continue
		}
		fileds := strings.Split(f, ",")
		subnet := strings.Split(fileds[3], "=")[1]
		subnets = append(subnets, subnet)
	}
	return subnets, nil
}

func dumpUplinkBrIPForward() ([]string, error) {
	cmdStr := fmt.Sprintf("sudo /usr/bin/ovs-ofctl -O Openflow13 dump-flows %s-%s table=30", BrName, "uplink")
	flows, err := dumpflows(cmdStr)
	if err != nil {
		return nil, err
	}
	subnets := []string{}
	for _, f := range flows {
		if !strings.Contains(f, "priority=200,ip") {
			continue
		}
		fileds := strings.Split(f, ",")
		s := strings.Split(fileds[3], "=")[1]
		subnet := strings.Split(s, " ")[0]
		subnets = append(subnets, subnet)
	}
	return subnets, nil
}

func dumpflows(cmdStr string) ([]string, error) {
	flowsByte, err := excuteCommand(cmdStr)
	if err != nil {
		return nil, err
	}

	flowOutStr := string(flowsByte)
	flowDB := strings.Split(flowOutStr, "\n")[1:]

	var flowList []string
	for _, flow := range flowDB {
		felem := strings.Fields(flow)
		if len(felem) > 2 {
			felem = append([]string{felem[2]}, felem[5:]...)
			fstr := strings.Join(felem, " ")
			flowList = append(flowList, fstr)
		}
	}

	return flowList, nil
}
