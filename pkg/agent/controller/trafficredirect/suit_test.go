package trafficredirect

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/everoute/trafficredirect/api/trafficredirect/v1alpha1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/everoute/everoute/pkg/agent/datapath"
	"github.com/everoute/everoute/pkg/metrics"
	"github.com/everoute/everoute/pkg/utils"
)

var (
	k8sClient          client.Client // You'll be using this client in your tests.
	testEnv            *envtest.Environment
	useExistingCluster bool
	ctx, cancel        = context.WithCancel(ctrl.SetupSignalHandler())
	tCtrl              *Reconciler
	dpMgr              *datapath.DpManager
)

const (
	RunTestWithExistingCluster = "TESTING_WITH_EXISTING_CLUSTER"
	brName                     = "bridgeTR"
	vds                        = "tr-vds"
	timeout                    = 10 * time.Second
	interval                   = time.Second
)

func TestTrafficRedirectController(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "tr Suite")
}

var _ = BeforeSuite(func() {
	var l klog.Level = 4
	l.Set("4")
	ctrl.SetLogger(klog.Background())
	if os.Getenv(RunTestWithExistingCluster) == "true" {
		By("testing with existing cluster")
		useExistingCluster = true
	}
	// Wait for policyrule test initialize DpManager, and then start flow relay test, avoid connection reset error
	time.Sleep(time.Second * 10)
	/*
		First, the envtest cluster is configured to read CRDs from the CRD directory Kubebuilder scaffolds for you.
	*/
	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		UseExistingCluster: &useExistingCluster,
		CRDInstallOptions: envtest.CRDInstallOptions{
			Paths:           []string{filepath.Join("..", "..", "..", "..", "ut_tmp")},
			CleanUpAfterUse: true,
		},
	}

	cfg, err := testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	err = v1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).Should(Succeed())

	k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme.Scheme,
		// disable metrics serving
		MetricsBindAddress: "0",
	})
	Expect(err).ToNot(HaveOccurred())
	Expect(k8sManager).ToNot(BeNil())

	Expect(datapath.ExcuteCommand(datapath.SetupBridgeChain, brName)).ToNot(HaveOccurred())

	dpMgr = datapath.NewDatapathManager(&datapath.DpManagerConfig{
		ManagedVDSMap: map[string]string{
			vds: brName,
		},
		MSVdsSet: sets.New[string](),
		TRConfig: map[string]datapath.VDSTRConfig{
			vds: datapath.VDSTRConfig{
				NicIn:  "in",
				NicOut: "out",
			},
		},
	}, nil, metrics.NewAgentMetric())
	dpMgr.InitializeDatapath(ctx)

	tCtrl = &Reconciler{
		Client: k8sManager.GetClient(),
		DpMgr:  dpMgr,
	}
	err = (tCtrl).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	go func() {
		err = k8sManager.Start(ctx)
		Expect(err).ToNot(HaveOccurred())
	}()

	k8sClient = k8sManager.GetClient()
	Expect(k8sClient).ToNot(BeNil())
	Expect(k8sManager.GetCache().WaitForCacheSync(ctx)).Should(BeTrue())
}, 60)

var _ = AfterSuite(func() {
	By("stop controller manager")
	cancel()
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
	Expect(datapath.ExcuteCommand(datapath.CleanBridgeChain, brName)).NotTo(HaveOccurred())
})

func validDpCache(g Gomega, r datapath.DPTRRuleSpec, refs sets.Set[string], exists bool) uint64 {
	id := utils.HashName(20, r)
	g.Expect(dpMgr.FlowIDToTRRules).ShouldNot(BeNil())
	g.Expect(dpMgr.TRRules).ShouldNot(BeNil())
	realR := dpMgr.TRRules[id]
	if !exists {
		g.Expect(realR).Should(BeNil())
		return 0
	}
	g.Expect(realR).ShouldNot(BeNil())
	g.Expect(realR.DPTRRuleSpec).Should(Equal(r))
	g.Expect(realR.Refs.Equal(refs)).Should(BeTrue())
	flowID := realR.FlowIDs[vds]
	g.Expect(flowID & 0x2000_0000_0800_0000).Should(Equal(uint64(0x2000_0000_0800_0000)))
	g.Expect(dpMgr.FlowIDToTRRules[flowID]).Should(Equal(realR))
	return flowID
}

func validDpFlow(g Gomega, srcMac, dstMac string, d datapath.DPDirect, flowID uint64, exists bool) {
	t := 110
	nextT := 115
	if d == datapath.DirEgress {
		t = 100
		nextT = 105
	}
	cmd := fmt.Sprintf("ovs-ofctl dump-flows %s-policy table=%d", brName, t)
	out, err := exec.Command("/bin/sh", "-c", cmd).CombinedOutput()
	g.Expect(err).ShouldNot(HaveOccurred())
	outF := strings.Split(string(out), "\n")
	exp := ""
	if srcMac != "" {
		exp = exp + ",dl_src=" + srcMac
	}
	if dstMac != "" {
		exp = exp + ",dl_dst=" + dstMac
	}

	if exists {
		g.Expect(outF).Should(ContainElement(ContainSubstring(fmt.Sprintf("cookie=%#x", flowID))))
		g.Expect(outF).Should(ContainElement(ContainSubstring("priority=100")))
		g.Expect(outF).Should(ContainElement(ContainSubstring(fmt.Sprintf("ip%s actions=resubmit(,%d)", exp, nextT))))
	} else {
		g.Expect(outF).ShouldNot(ContainElement(ContainSubstring(fmt.Sprintf("ip%s actions=resubmit(,%d)", exp, nextT))))
	}
}

func validNoDpFlow(g Gomega) {
	t := 110
	nextT := 115
	cmd := fmt.Sprintf("ovs-ofctl dump-flows %s-policy table=%d", brName, t)
	out, err := exec.Command("/bin/sh", "-c", cmd).CombinedOutput()
	g.Expect(err).ShouldNot(HaveOccurred())
	outF := strings.Split(string(out), "\n")
	g.Expect(outF).ShouldNot(ContainElement(ContainSubstring("priority=100")))
	g.Expect(outF).ShouldNot(ContainElement(ContainSubstring(fmt.Sprintf("actions=resubmit(,%d)", nextT))))

	t = 100
	nextT = 105
	cmd = fmt.Sprintf("ovs-ofctl dump-flows %s-policy table=%d", brName, t)
	out, err = exec.Command("/bin/sh", "-c", cmd).CombinedOutput()
	g.Expect(err).ShouldNot(HaveOccurred())
	outF = strings.Split(string(out), "\n")
	g.Expect(outF).ShouldNot(ContainElement(ContainSubstring("priority=100")))
	g.Expect(outF).ShouldNot(ContainElement(ContainSubstring(fmt.Sprintf("actions=resubmit(,%d)", nextT))))
}
