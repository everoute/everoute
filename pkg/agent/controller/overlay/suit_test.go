package overlay

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/everoute/everoute/pkg/agent/datapath"
	clientsetscheme "github.com/everoute/everoute/pkg/client/clientset_generated/clientset/scheme"
)

const (
	RunTestWithExistingCluster = "TESTING_WITH_EXISTING_CLUSTER"
	LocalNode                  = "nodelocal"
	Interval                   = time.Second
	Timeout                    = time.Minute
	BrName                     = "overlay"
)

var (
	testEnv           *envtest.Environment
	k8sClient         client.Client
	overlayReconciler *Reconciler
	ReplayChan        = make(chan event.GenericEvent)
)

func TestController(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Controller Suite")
}

var _ = BeforeSuite(func() {
	var useExistingCluster bool
	if os.Getenv(RunTestWithExistingCluster) == "true" {
		useExistingCluster = true
		By("testing with existing cluster")
	}

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		UseExistingCluster: &useExistingCluster,
		CRDInstallOptions: envtest.CRDInstallOptions{
			Paths:              []string{filepath.Join("..", "..", "..", "..", "deploy", "chart", "templates", "crds")},
			CleanUpAfterUse:    true,
			ErrorIfPathMissing: true,
		},
	}
	cfg, err := testEnv.Start()
	Expect(err).ToNot(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	err = clientsetscheme.AddToScheme(scheme.Scheme)
	Expect(err).ToNot(HaveOccurred())

	mgr, err := ctrl.NewManager(cfg, manager.Options{
		Scheme:             scheme.Scheme,
		MetricsBindAddress: "0",
	})
	Expect(err).ToNot(HaveOccurred())
	Expect(mgr).NotTo(BeNil())

	Expect(datapath.ExcuteCommand(datapath.SetupBridgeChain, BrName)).ToNot(HaveOccurred())
	Expect(datapath.ExcuteCommand(datapath.SetupCNIBridgeChain, BrName)).ToNot(HaveOccurred())
	Expect(datapath.ExcuteCommand(datapath.SetupProxyBridgeChain, BrName)).ToNot(HaveOccurred())
	Expect(datapath.ExcuteCommand(datapath.SetupTunnelBridgeChain, BrName)).ToNot(HaveOccurred())

	stopCh := ctrl.SetupSignalHandler()

	dpMgr, err := datapath.InitCNIDpMgrUT(stopCh, BrName, true, true)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(dpMgr).ShouldNot(BeNil())

	overlayReconciler = &Reconciler{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		LocalNode: LocalNode,
		UplinkBr:  dpMgr.GetUplinkBridgeOverlay(),
		syncChan:  ReplayChan,
	}
	err = overlayReconciler.SetupWithManager(mgr)
	Expect(err).ToNot(HaveOccurred())

	go func() {
		defer GinkgoRecover()
		err = mgr.Start(stopCh)
		Expect(err).ToNot(HaveOccurred())
	}()

	k8sClient = mgr.GetClient()
	Expect(k8sClient).NotTo(BeNil())

	Expect(mgr.GetCache().WaitForCacheSync(stopCh)).Should(BeTrue())
}, 60)

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})

func excuteCommand(commandStr string) ([]byte, error) {
	out, err := exec.Command("/bin/sh", "-c", commandStr).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to excute cmd: %v, error: %v", string(out), err)
	}

	return out, nil
}

func dumpRemoteFlows() ([]string, error) {
	var flowDump []string
	br := BrName + "-uplink"
	cmdStr := fmt.Sprintf("sudo /usr/bin/ovs-ofctl -O Openflow13 dump-flows %s table=70", br)
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

	flowDump = append(flowDump, flowList...)

	return flowDump, nil
}

func checkRemoteFlow(epIP string, remoteIP ...string) bool {
	allFlows, err := dumpRemoteFlows()
	if err != nil {
		return false
	}
	for i := range allFlows {
		f := allFlows[i]
		if !strings.Contains(f, fmt.Sprintf("nw_dst=%s", epIP)) {
			continue
		}
		if len(remoteIP) >0 && !strings.Contains(f, fmt.Sprintf("set_field:%s->tun_dst", remoteIP[0])) {
			continue
		}
		return true
	}
	return false
}
