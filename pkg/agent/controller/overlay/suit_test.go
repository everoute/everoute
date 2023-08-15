package overlay

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
	"sigs.k8s.io/controller-runtime/pkg/manager"

	clientsetscheme "github.com/everoute/everoute/pkg/client/clientset_generated/clientset/scheme"
)

const (
	RunTestWithExistingCluster = "TESTING_WITH_EXISTING_CLUSTER"
	LocalNode                  = "nodelocal"
	Interval                   = time.Second
	Timeout                    = time.Minute
)

var (
	testEnv           *envtest.Environment
	k8sClient         client.Client
	overlayReconciler *Reconciler
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
			Paths:              []string{filepath.Join("..", "..", "..", "..", "deploy", "chart", "crds")},
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

	overlayReconciler = &Reconciler{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		LocalNode: LocalNode,
	}
	err = overlayReconciler.SetupWithManager(mgr)
	Expect(err).ToNot(HaveOccurred())

	stopCh := ctrl.SetupSignalHandler()
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
