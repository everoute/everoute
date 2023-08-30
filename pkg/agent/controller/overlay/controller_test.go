package overlay

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"

	ercache "github.com/everoute/everoute/pkg/agent/controller/overlay/cache"
	"github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	ersource "github.com/everoute/everoute/pkg/source"
	ertypes "github.com/everoute/everoute/pkg/types"
)

var _ = Describe("overlay controller", func() {
	ctx := context.Background()
	nsName := "default"
	nodeName := "node1"
	internalIP := "1.1.1.1"
	node := corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeName,
		},
	}
	epName := "ep1"
	epIP := "123.1.1.1"
	epIndex := ercache.GenEpRefIndex(nsName, epName)
	ep := v1alpha1.Endpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      epName,
			Namespace: nsName,
		},
		Spec: v1alpha1.EndpointSpec{
			Type: v1alpha1.EndpointStatic,
			Reference: v1alpha1.EndpointReference{
				ExternalIDName:  "ep",
				ExternalIDValue: "ep1",
			},
		},
	}
	AfterEach(func() {
		Expect(k8sClient.DeleteAllOf(ctx, &v1alpha1.Endpoint{}, client.InNamespace(nsName))).Should(Succeed())
		Expect(k8sClient.DeleteAllOf(ctx, &corev1.Node{})).Should(Succeed())
		overlayReconciler.lock.Lock()
		overlayReconciler.nodeIPsCache = ercache.NewNodeIPsCache()
		overlayReconciler.lock.Unlock()
	})

	Context("test endpoint reconcile", func() {
		When("endpoint with exists node", func() {
			BeforeEach(func() {
				node = corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodeName,
					},
				}
				Expect(k8sClient.Create(ctx, &node)).ToNot(HaveOccurred())
				node.Status.Addresses = []corev1.NodeAddress{
					{
						Type:    corev1.NodeInternalIP,
						Address: internalIP,
					},
				}
				Expect(k8sClient.Status().Update(ctx, &node)).NotTo(HaveOccurred())
				Eventually(func() bool {
					return checkNodeIPsInCache(nodeName, internalIP)
				}, Timeout, Interval).Should(BeTrue())

				ep = v1alpha1.Endpoint{
					ObjectMeta: metav1.ObjectMeta{
						Name:      epName,
						Namespace: nsName,
					},
					Spec: v1alpha1.EndpointSpec{
						Type: v1alpha1.EndpointStatic,
						Reference: v1alpha1.EndpointReference{
							ExternalIDName:  "ep",
							ExternalIDValue: "ep1",
						},
					},
				}
				Expect(k8sClient.Create(ctx, &ep)).ToNot(HaveOccurred())
				ep.Status.Agents = []string{nodeName}
				ep.Status.IPs = []ertypes.IPAddress{
					ertypes.IPAddress(epIP),
				}
				Expect(k8sClient.Status().Update(ctx, &ep)).ToNot(HaveOccurred())
			})

			It("create endpoint status", func() {
				Eventually(func(g Gomega) {
					g.Expect(checkEndpointInCache(epIndex, nodeName, []string{epIP})).Should(BeTrue())
					g.Expect(checkRemoteFlow(epIP, internalIP)).Should(BeTrue())
				}, Timeout, Interval).Should(Succeed())
			})

			It("update endpoint ips", func() {
				ep.Status.IPs = []ertypes.IPAddress{
					ertypes.IPAddress("12.12.11.11"),
					ertypes.IPAddress("12.12.11.13"),
				}
				Expect(k8sClient.Status().Update(ctx, &ep)).ToNot(HaveOccurred())
				Eventually(func(g Gomega) {
					g.Expect(checkEndpointInCache(epIndex, nodeName, []string{"12.12.11.11", "12.12.11.13"})).Should(BeTrue())
					g.Expect(checkRemoteFlow(epIP)).Should(BeFalse())
					g.Expect(checkRemoteFlow("12.12.11.11", internalIP)).Should(BeTrue())
					g.Expect(checkRemoteFlow("12.12.11.13", internalIP)).Should(BeTrue())
				}, Timeout, Interval).Should(Succeed())
			})

			It("delete endpoint agents", func() {
				ep.Status.Agents = []string{}
				Expect(k8sClient.Status().Update(ctx, &ep)).NotTo(HaveOccurred())
				Eventually(func(g Gomega) {
					g.Expect(checkEndpointNotInCache(epIndex, nodeName)).Should(BeTrue())
					g.Expect(checkRemoteFlow(epIP)).Should(BeFalse())
				}, Timeout, Interval).Should(Succeed())
			})

			It("delete endpoint", func() {
				Expect(k8sClient.Delete(ctx, &ep)).NotTo(HaveOccurred())
				Eventually(func(g Gomega) {
					g.Expect(checkEndpointNotInCache(epIndex, nodeName)).Should(BeTrue())
					g.Expect(checkRemoteFlow(epIP)).Should(BeFalse())
				}, Timeout, Interval).Should(Succeed())
			})
		})
		When("endpoint with unexists node", func() {
			BeforeEach(func() {
				ep = v1alpha1.Endpoint{
					ObjectMeta: metav1.ObjectMeta{
						Name:      epName,
						Namespace: nsName,
					},
					Spec: v1alpha1.EndpointSpec{
						Type: v1alpha1.EndpointStatic,
						Reference: v1alpha1.EndpointReference{
							ExternalIDName:  "ep",
							ExternalIDValue: "ep1",
						},
					},
				}
				Expect(k8sClient.Create(ctx, &ep)).Should(Succeed())
			})

			It("endpoint status only with agent", func() {
				ep.Status.Agents = []string{nodeName}
				Expect(k8sClient.Status().Update(ctx, &ep)).Should(Succeed())
				time.Sleep(time.Minute)
				_, exists, err := overlayReconciler.nodeIPsCache.GetByKey(nodeName)
				Expect(err).Should(BeNil())
				Expect(exists).Should(BeFalse())
			})

			When("update endpoint status", func() {
				BeforeEach(func() {
					ep.Status.Agents = []string{nodeName}
					ep.Status.IPs = []ertypes.IPAddress{
						ertypes.IPAddress("12.12.12.12"),
					}
					Expect(k8sClient.Status().Update(ctx, &ep)).Should(Succeed())
				})

				It("endpoint status with agent and ip", func() {
					Eventually(func(g Gomega) {
						g.Expect(checkNodeIPsInCache(nodeName, "")).Should(BeTrue())
						g.Expect(checkEndpointInCache(epIndex, nodeName, []string{"12.12.12.12"})).Should(BeTrue())
					}, Timeout, Interval).Should(Succeed())
				})

				It("update endpoint ips", func() {
					ep.Status.IPs = []ertypes.IPAddress{
						ertypes.IPAddress("12.12.12.11"),
						ertypes.IPAddress("12.12.12.15"),
					}
					Expect(k8sClient.Status().Update(ctx, &ep)).Should(Succeed())
					Eventually(func(g Gomega) {
						g.Expect(checkNodeIPsInCache(nodeName, "")).Should(BeTrue())
						g.Expect(checkEndpointInCache(epIndex, nodeName, []string{"12.12.12.11", "12.12.12.15"})).Should(BeTrue())
					}, Timeout, Interval).Should(Succeed())
				})

				It("update endpoint agents", func() {
					ep.Status.Agents = []string{"node2", "node3"}
					Expect(k8sClient.Status().Update(ctx, &ep)).Should(Succeed())

					Eventually(func(g Gomega) {
						g.Expect(checkEndpointNotInCache(epIndex, nodeName)).Should(BeTrue())
						g.Expect(checkEndpointInCache(epIndex, "node2", []string{"12.12.12.12"})).Should(BeTrue())
						g.Expect(checkEndpointInCache(epIndex, "node3", []string{"12.12.12.12"})).Should(BeTrue())
					}, Timeout, Interval).Should(Succeed())
				})
			})
		})
	})

	Context("test node reconcile", func() {
		When("node without related endpoint", func() {
			BeforeEach(func() {
				node = corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodeName,
					},
				}
				Expect(k8sClient.Create(ctx, &node)).Should(Succeed())
			})

			It("create node without status", func() {
				Eventually(func() bool {
					_, exists, err := overlayReconciler.nodeIPsCache.GetByKey(nodeName)
					if err != nil {
						return false
					}
					return !exists
				}, Timeout, Interval).Should(BeTrue())
			})

			When("node has internalIP", func() {
				BeforeEach(func() {
					node.Status.Addresses = []corev1.NodeAddress{
						{
							Type:    corev1.NodeHostName,
							Address: "node",
						},
						{
							Type:    corev1.NodeInternalIP,
							Address: internalIP,
						},
					}
					Expect(k8sClient.Status().Update(ctx, &node)).Should(Succeed())
				})

				It("node with internalIP", func() {
					Eventually(func() bool {
						return checkNodeIPsInCache(nodeName, internalIP)
					}, Timeout, Interval).Should(BeTrue())
				})

				It("update node internalIP", func() {
					node.Status.Addresses = []corev1.NodeAddress{
						{
							Type:    corev1.NodeInternalIP,
							Address: "1.1.2.2",
						},
					}
					Expect(k8sClient.Status().Update(ctx, &node)).Should(Succeed())
					Eventually(func() bool {
						return checkNodeIPsInCache(nodeName, "1.1.2.2")
					}, Timeout, Interval).Should(BeTrue())
				})

				It("delete node internalIP", func() {
					node.Status.Addresses = []corev1.NodeAddress{
						{
							Type:    corev1.NodeExternalIP,
							Address: "1.1.2.2",
						},
					}
					Expect(k8sClient.Status().Update(ctx, &node)).Should(Succeed())
					Eventually(func() bool {
						return checkNodeIPsInCache(nodeName, "")
					}, Timeout, Interval).Should(BeTrue())
				})

				It("delete node", func() {
					Expect(k8sClient.Delete(ctx, &node)).Should(Succeed())
					Eventually(func() bool {
						_, exists, err := overlayReconciler.nodeIPsCache.GetByKey(nodeName)
						if err != nil {
							return false
						}
						return !exists
					}, Timeout, Interval).Should(BeTrue())
				})
			})
		})

		When("node with related endpoint", func() {
			BeforeEach(func() {
				ep = v1alpha1.Endpoint{
					ObjectMeta: metav1.ObjectMeta{
						Name:      epName,
						Namespace: nsName,
					},
					Spec: v1alpha1.EndpointSpec{
						Type: v1alpha1.EndpointStatic,
						Reference: v1alpha1.EndpointReference{
							ExternalIDName:  "ep",
							ExternalIDValue: "ep1",
						},
					},
				}
				Expect(k8sClient.Create(ctx, &ep)).Should(Succeed())
				ep.Status.Agents = []string{nodeName}
				ep.Status.IPs = []ertypes.IPAddress{
					ertypes.IPAddress(epIP),
				}
				Expect(k8sClient.Status().Update(ctx, &ep)).Should(Succeed())
				Eventually(func() bool {
					return checkEndpointInCache(epIndex, nodeName, []string{epIP})
				}, Timeout, Interval).Should(BeTrue())

				node = corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodeName,
					},
				}
				Expect(k8sClient.Create(ctx, &node)).Should(Succeed())
			})

			When("add node status with internalIP", func() {
				BeforeEach(func() {
					node.Status.Addresses = []corev1.NodeAddress{
						{
							Type:    corev1.NodeInternalIP,
							Address: internalIP,
						},
					}
					Expect(k8sClient.Status().Update(ctx, &node)).Should(Succeed())
					Eventually(func(g Gomega) {
						g.Expect(checkNodeIPsInCache(nodeName, internalIP)).Should(BeTrue())
						g.Expect(checkRemoteFlow(epIP, internalIP)).Should(BeTrue())
					}, Timeout, Interval).Should(Succeed())
				})

				It("add node internalIP", func() {
					Eventually(func(g Gomega) {
						g.Expect(checkNodeIPsInCache(nodeName, internalIP)).Should(BeTrue())
						g.Expect(checkRemoteFlow(epIP, internalIP)).Should(BeTrue())
					}, Timeout, Interval).Should(Succeed())
				})

				It("delete internalIP", func() {
					node.Status.Addresses = []corev1.NodeAddress{}
					Expect(k8sClient.Status().Update(ctx, &node)).Should(Succeed())
					Eventually(func(g Gomega) {
						g.Expect(checkNodeIPsInCache(nodeName, "")).Should(BeTrue())
						g.Expect(checkRemoteFlow(epIP)).Should(BeFalse())
					}, Timeout, Interval).Should(Succeed())
				})

				It("delete node", func() {
					Expect(k8sClient.Delete(ctx, &node)).Should(Succeed())
					Eventually(func(g Gomega) {
						_, exists, err := overlayReconciler.nodeIPsCache.GetByKey(nodeName)
						g.Expect(err).Should(BeNil())
						g.Expect(exists).Should(BeFalse())
						g.Expect(checkRemoteFlow(epIP)).Should(BeFalse())
					}, Timeout, Interval).Should(Succeed())
				})
			})
		})
	})

	Context("test replay", func() {
		node1 := &ercache.NodeIPs{
			Name: "replayNode1",
			IP:   "192.13.13.13",
			PodIPs: map[string]sets.String{
				"ep1": sets.NewString("193.1.1.1", "193.1.1.2"),
				"ep2": sets.NewString("193.1.1.3"),
			},
		}
		node2 := &ercache.NodeIPs{
			Name: "replayNode2",
			PodIPs: map[string]sets.String{
				"ep3": sets.NewString("193.1.1.4"),
			},
		}
		BeforeEach(func() {
			overlayReconciler.nodeIPsCache.Add(node1)
			overlayReconciler.nodeIPsCache.Add(node2)
		})
		AfterEach(func() {
			overlayReconciler.nodeIPsCache.Delete(node1)
			overlayReconciler.nodeIPsCache.Delete(node2)
		})
		It("replay flow", func() {
			ReplayChan <- ersource.NewReplayEvent()
			Eventually(func(g Gomega) {
				g.Expect(checkRemoteFlow("193.1.1.1", node1.IP)).Should(BeTrue())
				g.Expect(checkRemoteFlow("193.1.1.2", node1.IP)).Should(BeTrue())
				g.Expect(checkRemoteFlow("193.1.1.3", node1.IP)).Should(BeTrue())
				g.Expect(checkRemoteFlow("193.1.1.4")).Should(BeFalse())
			}, Timeout, Interval).Should(Succeed())
		})
	})
})

func checkEndpointInCache(epIndex, nodeName string, ips []string) bool {
	obj, exists, err := overlayReconciler.nodeIPsCache.GetByKey(nodeName)
	if err != nil {
		return false
	}

	if !exists {
		return false
	}

	o := obj.(*ercache.NodeIPs).DeepCopy()
	epIPs, ok := o.PodIPs[epIndex]
	if !ok {
		return false
	}
	if !epIPs.Equal(sets.NewString(ips...)) {
		return false
	}
	return true
}

func checkEndpointNotInCache(epIndex, nodeName string) bool {
	obj, exists, err := overlayReconciler.nodeIPsCache.GetByKey(nodeName)
	if err != nil {
		return false
	}

	if !exists {
		return true
	}

	o := obj.(*ercache.NodeIPs).DeepCopy()
	_, ok := o.PodIPs[epIndex]
	return !ok
}

func checkNodeIPsInCache(nodeName, nodeIP string) bool {
	obj, exists, err := overlayReconciler.nodeIPsCache.GetByKey(nodeName)
	if err != nil {
		return false
	}
	if !exists {
		return false
	}
	o := obj.(*ercache.NodeIPs).DeepCopy()
	return o.IP == nodeIP
}
