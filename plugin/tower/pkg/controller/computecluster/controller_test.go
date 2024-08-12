package computecluster

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	msconst "github.com/everoute/everoute/pkg/constants/ms"
	"github.com/everoute/everoute/plugin/tower/pkg/schema"
)

var _ = Describe("elf controller", func() {
	AfterEach(func() {
		server.TrackerFactory().ResetAll()
		err := erClient.CoreV1().ConfigMaps(towerSpace).Delete(ctx, msconst.CompluteClustersConfigMapName, metav1.DeleteOptions{})
		Expect(err).Should(BeNil())
		Eventually(func(g Gomega) {
			res, _ := erClient.CoreV1().ConfigMaps(towerSpace).Get(ctx, msconst.CompluteClustersConfigMapName, metav1.GetOptions{})
			g.Expect(res).Should(BeNil())
		}, timeout, interval).Should(Succeed())
	})

	Context("add elf ConfigMap", func() {
		It("er cluster associate elf", func() {
			erCluster := &schema.EverouteCluster{
				ObjectMeta: schema.ObjectMeta{
					ID: everouteCluster,
				},
				AgentELFClusters: []schema.AgentELFCluster{
					{LocalID: "elf1"},
					{LocalID: "elf2"},
				},
			}
			server.TrackerFactory().EverouteCluster().Create(erCluster)

			Eventually(func(g Gomega) {
				res, err := erClient.CoreV1().ConfigMaps(towerSpace).Get(ctx, msconst.CompluteClustersConfigMapName, metav1.GetOptions{})
				g.Expect(err).Should(BeNil())
				g.Expect(res.Data).ShouldNot(BeNil())
				g.Expect(len(res.Data)).Should(Equal(2))
				g.Expect(res.Data).Should(HaveKeyWithValue("elf1", ""))
				g.Expect(res.Data).Should(HaveKeyWithValue("elf2", ""))
			}, timeout, interval).Should(Succeed())
		})

		It("er cluster doesn't associate elf", func() {
			erCluster := &schema.EverouteCluster{
				ObjectMeta: schema.ObjectMeta{
					ID: everouteCluster,
				},
				AgentELFClusters: []schema.AgentELFCluster{},
			}
			server.TrackerFactory().EverouteCluster().Create(erCluster)

			Eventually(func(g Gomega) {
				res, err := erClient.CoreV1().ConfigMaps(towerSpace).Get(ctx, msconst.CompluteClustersConfigMapName, metav1.GetOptions{})
				g.Expect(err).Should(BeNil())
				g.Expect(len(res.Data)).Should(Equal(0))
			}, timeout, interval).Should(Succeed())
		})
	})

	Context("update elf ConfigMap", func() {
		BeforeEach(func() {
			erCluster := &schema.EverouteCluster{
				ObjectMeta: schema.ObjectMeta{
					ID: everouteCluster,
				},
				AgentELFClusters: []schema.AgentELFCluster{
					{LocalID: "elf1"},
					{LocalID: "elf2"},
				},
			}
			server.TrackerFactory().EverouteCluster().Create(erCluster)
			Eventually(func(g Gomega) {
				res, err := erClient.CoreV1().ConfigMaps(towerSpace).Get(ctx, msconst.CompluteClustersConfigMapName, metav1.GetOptions{})
				g.Expect(err).Should(BeNil())
				g.Expect(res.Data).ShouldNot(BeNil())
				g.Expect(len(res.Data)).Should(Equal(2))
				g.Expect(res.Data).Should(HaveKeyWithValue("elf1", ""))
				g.Expect(res.Data).Should(HaveKeyWithValue("elf2", ""))
				g.Expect(controller.reconcileQueue.Len()).Should(Equal(0))
			}, timeout, interval).Should(Succeed())
		})

		It("add associate elf cluster", func() {
			erCluster := &schema.EverouteCluster{
				ObjectMeta: schema.ObjectMeta{
					ID: everouteCluster,
				},
				AgentELFClusters: []schema.AgentELFCluster{
					{LocalID: "elf1"},
					{LocalID: "elf2"},
					{LocalID: "elf"},
				},
			}
			server.TrackerFactory().EverouteCluster().CreateOrUpdate(erCluster)

			Eventually(func(g Gomega) {
				res, err := erClient.CoreV1().ConfigMaps(towerSpace).Get(ctx, msconst.CompluteClustersConfigMapName, metav1.GetOptions{})
				g.Expect(err).Should(BeNil())
				g.Expect(res.Data).ShouldNot(BeNil())
				g.Expect(len(res.Data)).Should(Equal(3))
				g.Expect(res.Data).Should(HaveKeyWithValue("elf1", ""))
				g.Expect(res.Data).Should(HaveKeyWithValue("elf2", ""))
				g.Expect(res.Data).Should(HaveKeyWithValue("elf", ""))
			}, timeout, interval).Should(Succeed())
		})

		It("del assocaite elf cluster", func() {
			erCluster := &schema.EverouteCluster{
				ObjectMeta: schema.ObjectMeta{
					ID: everouteCluster,
				},
				AgentELFClusters: []schema.AgentELFCluster{
					{LocalID: "elf2"},
				},
			}
			server.TrackerFactory().EverouteCluster().CreateOrUpdate(erCluster)
			Eventually(func(g Gomega) {
				res, err := erClient.CoreV1().ConfigMaps(towerSpace).Get(ctx, msconst.CompluteClustersConfigMapName, metav1.GetOptions{})
				g.Expect(err).Should(BeNil())
				g.Expect(res.Data).ShouldNot(BeNil())
				g.Expect(len(res.Data)).Should(Equal(1))
				g.Expect(res.Data).Should(HaveKeyWithValue("elf2", ""))
			}, timeout, interval).Should(Succeed())
		})

		It("update ConfigMap", func() {
			By("update ConfigMap")
			res, err := erClient.CoreV1().ConfigMaps(towerSpace).Get(ctx, msconst.CompluteClustersConfigMapName, metav1.GetOptions{})
			Expect(err).Should(BeNil())
			res.Data["test"] = ""
			_, err = erClient.CoreV1().ConfigMaps(towerSpace).Update(ctx, res, metav1.UpdateOptions{})
			Expect(err).Should(BeNil())

			By("check ConfigMap has been updated")
			res, err = erClient.CoreV1().ConfigMaps(towerSpace).Get(ctx, msconst.CompluteClustersConfigMapName, metav1.GetOptions{})
			Expect(err).Should(BeNil())
			Expect(res.Data).Should(HaveKey("test"))

			Eventually(func(g Gomega) {
				res, err := erClient.CoreV1().ConfigMaps(towerSpace).Get(ctx, msconst.CompluteClustersConfigMapName, metav1.GetOptions{})
				g.Expect(err).Should(BeNil())
				g.Expect(res.Data).ShouldNot(BeNil())
				g.Expect(len(res.Data)).Should(Equal(2))
				g.Expect(res.Data).Should(HaveKeyWithValue("elf2", ""))
				g.Expect(res.Data).Should(HaveKeyWithValue("elf1", ""))
			}, timeout, interval).Should(Succeed())
		})
	})
})

func TestHandleConfigMap(t *testing.T) {
	ns := "test"
	tests := []struct {
		name     string
		arg      interface{}
		queueLen int
	}{
		{
			name: "normal",
			arg: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      msconst.CompluteClustersConfigMapName,
					Namespace: ns,
				},
			},
			queueLen: 1,
		},
		{
			name: "unexpect ConfigMap name",
			arg: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test name",
					Namespace: ns,
				},
			},
			queueLen: 0,
		},
		{
			name: "unexpect ConfigMap namespace",
			arg: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      msconst.CompluteClustersConfigMapName,
					Namespace: "test-error-ns",
				},
			},
			queueLen: 0,
		},
		{
			name: "delete object",
			arg: cache.DeletedFinalStateUnknown{
				Obj: &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      msconst.CompluteClustersConfigMapName,
						Namespace: ns,
					},
				},
			},
			queueLen: 1,
		},
	}

	for _, c := range tests {
		controller := &Controller{
			ConfigMapNamespace: ns,
			reconcileQueue:     workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		}
		controller.handleConfigMap(c.arg)
		if controller.reconcileQueue.Len() != c.queueLen {
			t.Errorf("test %s failed, expect is %d, real is %d", c.name, c.queueLen, controller.reconcileQueue.Len())
		}
	}
}

func TestHandleConfigMapUpdate(t *testing.T) {
	var makeConfigMapData = func(keys ...string) map[string]string {
		res := make(map[string]string, len(keys))
		for _, i := range keys {
			res[i] = ""
		}
		return res
	}
	ns := "test"
	tests := []struct {
		name     string
		oldArg   interface{}
		newArg   interface{}
		queueLen int
	}{
		{
			name: "normal",
			oldArg: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      msconst.CompluteClustersConfigMapName,
					Namespace: ns,
				},
				Data: makeConfigMapData("k1", "k2"),
			},
			newArg: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      msconst.CompluteClustersConfigMapName,
					Namespace: ns,
				},
				Data: makeConfigMapData("k1", "k3"),
			},
			queueLen: 1,
		},
		{
			name: "unexpect ConfigMap namespace",
			oldArg: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      msconst.CompluteClustersConfigMapName,
					Namespace: ns,
				},
				Data: makeConfigMapData("k1", "k2"),
			},
			newArg: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      msconst.CompluteClustersConfigMapName,
					Namespace: "test-error-ns",
				},
				Data: makeConfigMapData("k1", "k3"),
			},
			queueLen: 0,
		},
		{
			name: "unexpect ConfigMap name",
			oldArg: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      msconst.CompluteClustersConfigMapName,
					Namespace: ns,
				},
				Data: makeConfigMapData("k1", "k2"),
			},
			newArg: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-error-name",
					Namespace: ns,
				},
				Data: makeConfigMapData("k1", "k3"),
			},
			queueLen: 0,
		},
		{
			name: "data is all empty",
			oldArg: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      msconst.CompluteClustersConfigMapName,
					Namespace: ns,
				},
				Data: nil,
			},
			newArg: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      msconst.CompluteClustersConfigMapName,
					Namespace: ns,
				},
				Data: make(map[string]string),
			},
			queueLen: 0,
		},
		{
			name: "old data is empty",
			oldArg: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      msconst.CompluteClustersConfigMapName,
					Namespace: ns,
				},
				Data: make(map[string]string),
			},
			newArg: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      msconst.CompluteClustersConfigMapName,
					Namespace: ns,
				},
				Data: makeConfigMapData("k1"),
			},
			queueLen: 1,
		},
		{
			name: "data is same",
			oldArg: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      msconst.CompluteClustersConfigMapName,
					Namespace: ns,
				},
				Data: makeConfigMapData("k1", "k2"),
			},
			newArg: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      msconst.CompluteClustersConfigMapName,
					Namespace: ns,
				},
				Data: makeConfigMapData("k1", "k2"),
			},
			queueLen: 0,
		},
	}

	for _, c := range tests {
		controller := &Controller{
			ConfigMapNamespace: ns,
			reconcileQueue:     workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		}
		controller.handleConfigMapUpdate(c.oldArg, c.newArg)
		if controller.reconcileQueue.Len() != c.queueLen {
			t.Errorf("test %s failed, expect is %d, real is %d", c.name, c.queueLen, controller.reconcileQueue.Len())
		}
	}
}

func TestHandleCluster(t *testing.T) {
	tests := []struct {
		name     string
		arg      interface{}
		queueLen int
	}{
		{
			name: "normal",
			arg: &schema.EverouteCluster{
				ObjectMeta: schema.ObjectMeta{
					ID: everouteCluster,
				},
			},
			queueLen: 1,
		},
		{
			name: "unexpected everoute cluster",
			arg: &schema.EverouteCluster{
				ObjectMeta: schema.ObjectMeta{
					ID: "test-error-id",
				},
			},
			queueLen: 0,
		},
		{
			name: "delete everoute cluster",
			arg: cache.DeletedFinalStateUnknown{
				Obj: &schema.EverouteCluster{
					ObjectMeta: schema.ObjectMeta{
						ID: everouteCluster,
					},
				},
			},
			queueLen: 1,
		},
	}

	for _, c := range tests {
		controller := &Controller{
			EverouteClusterID: everouteCluster,
			reconcileQueue:    workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		}
		controller.handleCluster(c.arg)
		if controller.reconcileQueue.Len() != c.queueLen {
			t.Errorf("test %s failed, expect is %d, real is %d", c.name, c.queueLen, controller.reconcileQueue.Len())
		}
	}
}

func TestHandleClusterUpdate(t *testing.T) {
	tests := []struct {
		name     string
		oldObj   interface{}
		newObj   interface{}
		queueLen int
	}{
		{
			name: "normal",
			oldObj: &schema.EverouteCluster{
				ObjectMeta: schema.ObjectMeta{
					ID: everouteCluster,
				},
				AgentELFClusters: []schema.AgentELFCluster{
					{
						LocalID: "elf1",
					},
				},
			},
			newObj: &schema.EverouteCluster{
				ObjectMeta: schema.ObjectMeta{
					ID: everouteCluster,
				},
				AgentELFClusters: []schema.AgentELFCluster{},
			},
			queueLen: 1,
		},
		{
			name: "elfid is same, other info different",
			oldObj: &schema.EverouteCluster{
				ObjectMeta: schema.ObjectMeta{
					ID: everouteCluster,
				},
				AgentELFClusters: []schema.AgentELFCluster{
					{
						LocalID: "elf1",
					},
				},
				EnableLogging: true,
			},
			newObj: &schema.EverouteCluster{
				ObjectMeta: schema.ObjectMeta{
					ID: everouteCluster,
				},
				AgentELFClusters: []schema. AgentELFCluster{
					{
						LocalID: "elf1",
					},
				},
			},
			queueLen: 0,
		},
		{
			name: "unexpected everoute cluster",
			oldObj: &schema.EverouteCluster{
				ObjectMeta: schema.ObjectMeta{
					ID: everouteCluster,
				},
				AgentELFClusters: []schema.AgentELFCluster{
					{
						LocalID: "elf1",
					},
				},
			},
			newObj: &schema.EverouteCluster{
				ObjectMeta: schema.ObjectMeta{
					ID: "test-error-id",
				},
				AgentELFClusters: []schema.AgentELFCluster{},
			},
			queueLen: 0,
		},
	}
	for _, c := range tests {
		controller := &Controller{
			EverouteClusterID: everouteCluster,
			reconcileQueue:    workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		}
		controller.handleClusterUpdate(c.oldObj, c.newObj)
		if controller.reconcileQueue.Len() != c.queueLen {
			t.Errorf("test %s failed, expect is %d, real is %d", c.name, c.queueLen, controller.reconcileQueue.Len())
		}
	}
}
