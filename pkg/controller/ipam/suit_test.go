package ipam

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	ipamv1alpha1 "github.com/everoute/ipam/api/ipam/v1alpha1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var (
	k8sClient          client.Client // You'll be using this client in your tests.
	testEnv            *envtest.Environment
	useExistingCluster bool
	ctx, cancel        = context.WithCancel(ctrl.SetupSignalHandler())
)

const (
	RunTestWithExistingCluster = "TESTING_WITH_EXISTING_CLUSTER"
	poolNs                     = "test-ipam-gw"
	poolName                   = "pool"
	timeout                    = time.Second * 10
	interval                   = time.Second
)

func TestPolicyController(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ipam controller suite")
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
			Paths:           []string{filepath.Join("..", "..", "..", "deploy", "chart", "templates", "crds")},
			CleanUpAfterUse: true,
		},
	}

	cfg, err := testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	err = securityv1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())
	err = corev1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())
	Expect(ipamv1alpha1.AddToScheme(scheme.Scheme)).NotTo(HaveOccurred())

	k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme.Scheme,
		// disable metrics serving
		MetricsBindAddress: "0",
	})
	Expect(err).ToNot(HaveOccurred())
	Expect(k8sManager).ToNot(BeNil())

	err = (&Reconciler{
		Client:       k8sManager.GetClient(),
		GWIPPoolNs:   poolNs,
		GWIPPoolName: poolName,
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	go func() {
		err = k8sManager.Start(ctx)
		Expect(err).ToNot(HaveOccurred())
	}()

	k8sClient = k8sManager.GetClient()
	Expect(k8sClient).ToNot(BeNil())
	ns := corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: poolNs,
		},
	}
	Expect(k8sClient.Create(ctx, &ns)).ToNot(HaveOccurred())
	k8sManager.GetCache().WaitForCacheSync(ctx)
}, 60)

var _ = AfterSuite(func() {
	By("stop controller manager")
	cancel()
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})
