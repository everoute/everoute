package proxy

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/everoute/everoute/pkg/agent/controller/proxy/cache"
	"github.com/everoute/everoute/pkg/agent/datapath"
	dpcache "github.com/everoute/everoute/pkg/agent/datapath/cache"
	clientsetscheme "github.com/everoute/everoute/pkg/client/clientset_generated/clientset/scheme"
	ertype "github.com/everoute/everoute/pkg/types"
)

const (
	RunTestWithExistingCluster = "TESTING_WITH_EXISTING_CLUSTER"
	BrName                     = "proxybrUT"
	Interval                   = time.Second
	Timeout                    = time.Second * 10
	localNode                  = "nodelocal"

	ipsetNs = "test-ipset"
)

var (
	k8sClient          client.Client
	useExistingCluster bool
	testEnv            *envtest.Environment
	proxyController    Reconciler
	svcIndex           *dpcache.SvcIndex
	syncChan           chan event.GenericEvent
	ctx, cancel        = context.WithCancel(ctrl.SetupSignalHandler())

	ipsetCtrl IPSetCtrl
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
			Paths:           []string{filepath.Join("..", "..", "..", "..", "deploy", "chart", "templates", "crds")},
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

	dpMgr, err := datapath.InitCNIDpMgrUT(ctx.Done(), BrName, true, false, false)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(dpMgr).ShouldNot(BeNil())

	natbrs := dpMgr.GetNatBridges()
	Expect(len(natbrs) == 1).Should(BeTrue())
	svcIndex = natbrs[0].GetSvcIndexCache()
	Expect(svcIndex).ShouldNot(BeNil())

	syncChan = make(chan event.GenericEvent)
	proxyController = Reconciler{
		Client:    k8sManager.GetClient(),
		Scheme:    k8sManager.GetScheme(),
		DpMgr:     dpMgr,
		LocalNode: localNode,
		SyncChan:  syncChan,
		ProxyAll:  true,
	}
	err = proxyController.SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())
	Expect(proxyController.svcLBCache).ToNot(BeNil())

	ipsetCtrl = IPSetCtrl{
		Client: k8sManager.GetClient(),
		LBSet:  newTestIPSet("lbsvc"),
		TCPSet: newTestIPSet("npsvc-tcp"),
		UDPSet: newTestIPSet("npsvc-udp"),
	}
	Expect(ipsetCtrl.SetupWithManager(k8sManager)).ToNot(HaveOccurred())

	go func() {
		defer GinkgoRecover()
		err := k8sManager.Start(ctx)
		Expect(err).ToNot(HaveOccurred())
	}()

	k8sClient = k8sManager.GetClient()
	Expect(k8sClient).ToNot(BeNil())
	Expect(k8sManager.GetCache().WaitForCacheSync(ctx)).Should(BeTrue())
	Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ipsetNs}})).ShouldNot(HaveOccurred())
}, 60)

var _ = AfterSuite(func() {
	By("stop controller manager")
	cancel()
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
	Expect(datapath.ExcuteCommand(datapath.CleanBridgeChain, BrName)).NotTo(HaveOccurred())
	Expect(datapath.ExcuteCommand(datapath.CleanProxyBridgeChain, BrName)).NotTo(HaveOccurred())
})

type testSvcOvsInfo struct {
	// key is portname, value is groupid
	groupMap map[string]map[ertype.TrafficPolicyType]uint32
	// the first key is ip, the second key is portname, the value is flowid
	lbMap map[string]map[string]uint64
	// the first key is ip, the second key is portname, the value is flowid
	sessionAffinityMap map[string]map[string]uint64
}

func genTestSvcOvsInfo(dpInfo *dpcache.SvcOvsInfo) *testSvcOvsInfo {
	res := &testSvcOvsInfo{
		groupMap:           make(map[string]map[ertype.TrafficPolicyType]uint32),
		lbMap:              make(map[string]map[string]uint64),
		sessionAffinityMap: make(map[string]map[string]uint64),
	}
	gps := dpInfo.GetAllGroups()
	for i := range gps {
		if res.groupMap[gps[i].PortName] == nil {
			res.groupMap[gps[i].PortName] = make(map[ertype.TrafficPolicyType]uint32)
		}
		res.groupMap[gps[i].PortName][gps[i].TrafficPolicy] = gps[i].Group.GroupID
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

func genName() string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyz-")
	b := make([]rune, 7)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	if b[6] == '-' {
		b[6] = rune('a')
	}
	return string(b)
}

func genSvcName() string {
	return "svc-" + genName()
}

func genPortName() string {
	return "port-" + genName()
}

func genPortNumber() int32 {
	return rand.Int31n(10000) + 1
}

func genNodePortNumber() int32 {
	return rand.Int31n(2767) + 30000
}

func genPortProto() corev1.Protocol {
	protos := []corev1.Protocol{corev1.ProtocolTCP, corev1.ProtocolSCTP, corev1.ProtocolUDP}
	i := rand.Intn(3)
	return protos[i]
}

func genIP() string {
	ipv6 := (rand.Intn(8) == 0)
	if ipv6 {
		return "fc:99::44"
	}
	return fmt.Sprintf("%d.%d.%d.%d", rand.Intn(255)+1, rand.Intn(255), rand.Intn(255), rand.Intn(255))
}
