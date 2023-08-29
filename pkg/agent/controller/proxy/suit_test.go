package proxy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/everoute/everoute/pkg/agent/controller/proxy/cache"
	"github.com/everoute/everoute/pkg/agent/datapath"
	dpcache "github.com/everoute/everoute/pkg/agent/datapath/cache"
	clientsetscheme "github.com/everoute/everoute/pkg/client/clientset_generated/clientset/scheme"
)

const (
	RunTestWithExistingCluster = "TESTING_WITH_EXISTING_CLUSTER"
	BrName                     = "proxybrUT"
	Interval                   = time.Second
	Timeout                    = time.Minute
)

var (
	k8sClient          client.Client
	useExistingCluster bool
	testEnv            *envtest.Environment
	proxyController    Reconciler
	svcIndex           *dpcache.SvcIndex
	syncChan           chan event.GenericEvent
)

func TestProxyController(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ProxyController Suite")
}

var _ = BeforeSuite(func() {
	if os.Getenv(RunTestWithExistingCluster) == "true" {
		By("testing with existing cluster")
		useExistingCluster = true
	}

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		UseExistingCluster: &useExistingCluster,
		CRDInstallOptions: envtest.CRDInstallOptions{
			Paths:           []string{filepath.Join("..", "..", "..", "..", "deploy", "chart", "crds")},
			CleanUpAfterUse: true,
		},
	}

	// start envtest cluster
	cfg, err := testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	err = clientsetscheme.AddToScheme(scheme.Scheme)
	Expect(err).Should(Succeed())

	k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:             scheme.Scheme,
		MetricsBindAddress: "0",
	})
	Expect(err).ToNot(HaveOccurred())
	Expect(k8sManager).ToNot(BeNil())

	Expect(datapath.ExcuteCommand(datapath.SetupBridgeChain, BrName)).ToNot(HaveOccurred())
	Expect(datapath.ExcuteCommand(datapath.SetupCNIBridgeChain, BrName)).ToNot(HaveOccurred())
	Expect(datapath.ExcuteCommand(datapath.SetupProxyBridgeChain, BrName)).ToNot(HaveOccurred())

	stopCh := ctrl.SetupSignalHandler()

	dpMgr, err := datapath.InitCNIDpMgrUT(stopCh, BrName, true, false)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(dpMgr).ShouldNot(BeNil())

	natbrs := dpMgr.GetNatBridges()
	Expect(len(natbrs) == 1).Should(BeTrue())
	svcIndex = natbrs[0].GetSvcIndexCache()
	Expect(svcIndex).ShouldNot(BeNil())

	syncChan = make(chan event.GenericEvent)
	proxyController = Reconciler{
		Client:   k8sManager.GetClient(),
		Scheme:   k8sManager.GetScheme(),
		DpMgr:    dpMgr,
		SyncChan: syncChan,
	}
	err = proxyController.SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())
	Expect(proxyController.baseSvcCache).ToNot(BeNil())

	go func() {
		defer GinkgoRecover()
		err := k8sManager.Start(stopCh)
		Expect(err).ToNot(HaveOccurred())
	}()

	k8sClient = k8sManager.GetClient()
	Expect(k8sClient).ToNot(BeNil())
	Expect(k8sManager.GetCache().WaitForCacheSync(stopCh)).Should(BeTrue())

}, 60)

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
	Expect(datapath.ExcuteCommand(datapath.CleanBridgeChain, BrName)).NotTo(HaveOccurred())
	Expect(datapath.ExcuteCommand(datapath.CleanProxyBridgeChain, BrName)).NotTo(HaveOccurred())
})

func equalBaseSvc(b1 *cache.BaseSvc, b2 *cache.BaseSvc) bool {
	if b1 == nil && b2 == nil {
		return true
	}
	if b1 == nil || b2 == nil {
		return false
	}

	if b1.SvcID != b2.SvcID {
		return false
	}

	if b1.SvcType != b2.SvcType {
		return false
	}

	if add, del := b1.DiffClusterIPs(b2); len(add) != 0 || len(del) != 0 {
		return false
	}

	if b1.ChangeAffinityMode(b2) || b1.ChangeAffinityTimeout(b2) {
		return false
	}

	if add, upd, del := b1.DiffPorts(b2); len(add) != 0 || len(upd) != 0 || len(del) != 0 {
		return false
	}

	return true
}

type testSvcOvsInfo struct {
	// key is portname, value is groupid
	groupMap map[string]uint32
	// the first key is ip, the second key is portname, the value is flowid
	lbMap map[string]map[string]uint64
	// the first key is ip, the second key is portname, the value is flowid
	sessionAffinityMap map[string]map[string]uint64
}

func genTestSvcOvsInfo(dpInfo *dpcache.SvcOvsInfo) *testSvcOvsInfo {
	res := &testSvcOvsInfo{
		groupMap:           make(map[string]uint32),
		lbMap:              make(map[string]map[string]uint64),
		sessionAffinityMap: make(map[string]map[string]uint64),
	}
	gps := dpInfo.GetAllGroups()
	for i := range gps {
		res.groupMap[gps[i].PortName] = gps[i].Group.GroupID
	}
	lbFlows := dpInfo.GetAllLBFlows()
	for i := range lbFlows {
		cur := lbFlows[i]
		if res.lbMap[cur.LBIP] == nil {
			res.lbMap[cur.LBIP] = make(map[string]uint64)
		}
		res.lbMap[cur.LBIP][cur.PortName] = cur.Flow.FlowID
	}
	sessionFlows := dpInfo.GetAllSessionAffinityFlows()
	for i := range sessionFlows {
		cur := sessionFlows[i]
		if res.sessionAffinityMap[cur.LBIP] == nil {
			res.sessionAffinityMap[cur.LBIP] = make(map[string]uint64)
		}
		res.sessionAffinityMap[cur.LBIP][cur.PortName] = cur.Flow.FlowID
	}
	return res
}

func equalBackend(b1 *cache.Backend, b2 *cache.Backend) bool {
	if b1 == nil && b2 == nil {
		return true
	}
	if b1 == nil || b2 == nil {
		return false
	}

	if b1.IP != b2.IP || b1.Port != b2.Port || b1.Protocol != b2.Protocol {
		return false
	}

	return b1.ServicePortRefs.Equal(b2.ServicePortRefs)
}
