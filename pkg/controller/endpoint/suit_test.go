package endpoint

import (
	"context"
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

	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
)

var (
	k8sClient          client.Client // You'll be using this client in your tests.
	testEnv            *envtest.Environment
	useExistingCluster bool
	ctx                = context.Background()
	timeout            = time.Minute
	interval           = time.Second
)

const (
	RunTestWithExistingCluster = "TESTING_WITH_EXISTING_CLUSTER"
	strictMacNs                = "strict-mac"
)

func TestStrictMacController(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "endpoint Suite")
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

	k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme.Scheme,
		// disable metrics serving
		MetricsBindAddress: "0",
	})
	Expect(err).ToNot(HaveOccurred())
	Expect(k8sManager).ToNot(BeNil())

	err = (&StrictMacController{
		Client: k8sManager.GetClient(),
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	go func() {
		err = k8sManager.Start(ctrl.SetupSignalHandler())
		Expect(err).ToNot(HaveOccurred())
	}()

	k8sClient = k8sManager.GetClient()
	Expect(k8sClient).ToNot(BeNil())

	ns := corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: strictMacNs,
		},
	}
	Expect(k8sClient.Create(ctx, &ns)).ToNot(HaveOccurred())
}, 60)

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})

func makeMap(kvs ...string) map[string]string {
	m := make(map[string]string)
	i := 0
	for i < len(kvs) {
		m[kvs[i]] = kvs[i+1]
		i += 2
	}

	return m
}

func newEp(strictMac bool, etype securityv1alpha1.EndpointType, labels map[string]string) *securityv1alpha1.Endpoint {
	ep := securityv1alpha1.Endpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ep",
			Namespace: "ns",
			Labels:    labels,
		},
		Spec: securityv1alpha1.EndpointSpec{
			StrictMac: strictMac,
			Type:      etype,
			VID:       uint32(rand.Int31n(100)),
		},
	}
	return &ep
}
