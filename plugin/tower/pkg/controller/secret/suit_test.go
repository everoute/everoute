package secret

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

var (
	k8sClient          client.Client // You'll be using this client in your tests.
	testEnv            *envtest.Environment
	useExistingCluster bool
	ctx, cancel        = context.WithCancel(ctrl.SetupSignalHandler())
	timeout            = time.Second * 20
	interval           = time.Second
	queue              = make(chan event.GenericEvent, 1)
	pCtrl              *Process
	mockCtl            *gomock.Controller
	towerSpace         = "tower-space"
)

const (
	RunTestWithExistingCluster = "TESTING_WITH_EXISTING_CLUSTER"
)

func TestSecretController(t *testing.T) {
	RegisterFailHandler(Fail)
	mockCtl = gomock.NewController(t)
	defer mockCtl.Finish()
	RunSpecs(t, "secret Suite")
}

var _ = BeforeSuite(func() {
	if os.Getenv(RunTestWithExistingCluster) == "true" {
		By("testing with existing cluster")
		useExistingCluster = true
	}

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		UseExistingCluster: &useExistingCluster,
	}

	ctrl.SetLogger(klog.Background())
	cfg, err := testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	err = corev1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme.Scheme,
		// disable metrics serving
		MetricsBindAddress: "0",
	})
	Expect(err).ToNot(HaveOccurred())
	Expect(k8sManager).ToNot(BeNil())
	pCtrl = &Process{
		Namespace: towerSpace,
		ERCli:     k8sManager.GetClient(),
		TowerCli:  k8sManager.GetClient(),
	}
	err = pCtrl.SetupWithManager(k8sManager, queue, k8sManager.GetCache())
	Expect(err).ToNot(HaveOccurred())

	go func() {
		err = k8sManager.Start(ctx)
		Expect(err).ToNot(HaveOccurred())
	}()

	k8sClient = k8sManager.GetClient()
	Expect(k8sClient).ToNot(BeNil())

	ns := corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: towerSpace,
		},
	}
	Expect(k8sClient.Create(ctx, &ns)).ToNot(HaveOccurred())
}, 60)

var _ = AfterSuite(func() {
	By("stop controller manager")
	cancel()
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})
