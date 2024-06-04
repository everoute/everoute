package k8s

import (
	"context"
	"sync"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	svc "github.com/everoute/everoute/pkg/apis/service/v1alpha1"
)

var _ = Describe("endpoints controller", Ordered, func() {
	ctx := context.Background()
	ns := "testep"
	nsSelector := client.InNamespace(ns)
	epNamespacedName := types.NamespacedName{
		Name:      "eps",
		Namespace: ns,
	}
	epNamespacedNameHeadless := types.NamespacedName{
		Name:      "eps-headless",
		Namespace: ns,
	}
	node1 := "node1"
	node2 := "node2"
	ip1 := "10.0.0.3"
	ip2 := "10.0.0.4"
	ip3 := "10.0.0.5"
	portName1 := "http"
	portName2 := "ssh"
	var mockGet *gomonkey.Patches
	var mockMutex sync.Mutex
	BeforeAll(func() {
		Eventually(func(g Gomega) {
			creatNS := corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: ns,
				},
			}
			req := types.NamespacedName{Name: ns}
			err := k8sClient.Get(ctx, req, &creatNS)
			if err != nil {
				g.Expect(errors.IsNotFound(err)).Should(BeTrue())
				g.Expect(k8sClient.Create(ctx, &creatNS)).Should(Succeed())
			}
		}, timeout, interval).Should(Succeed())

		mockGet = gomonkey.NewPatches()
		fn := func(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			mockMutex.Lock()
			defer mockMutex.Unlock()
			if v, ok := obj.(*corev1.Service); ok {
				if key.Name == "eps" {
					v.Spec.ClusterIP = "1.1.1.1"
					return nil
				}
				if key.Name == "eps-headless" {
					v.Spec.ClusterIP = "None"
					return nil
				}
			}
			var out error
			mockGet.Origin(func() {
				out = k8sClient.Get(ctx, key, obj, opts...)
			})
			return out
		}
		mockGet.ApplyMethodFunc(k8sClient, "Get", fn)
	})
	AfterAll(func() {
		mockMutex.Lock()
		defer mockMutex.Unlock()
		mockGet.Reset()
	})

	Context("endpoints with only one port", func() {
		endpoints := corev1.Endpoints{
			ObjectMeta: metav1.ObjectMeta{
				Name:      epNamespacedName.Name,
				Namespace: epNamespacedName.Namespace,
			},
			Subsets: []corev1.EndpointSubset{
				{
					Addresses: []corev1.EndpointAddress{
						{
							IP: ip1,
						}, {
							IP:       ip2,
							NodeName: &node2,
						},
					},
					Ports: []corev1.EndpointPort{
						{
							Port:     80,
							Protocol: corev1.ProtocolTCP,
						},
					},
				},
			},
		}
		BeforeEach(func() {
			createEndpoints := endpoints
			Expect(k8sClient.Create(ctx, &createEndpoints)).Should(Succeed())
		})

		AfterEach(func() {
			ep := corev1.Endpoints{}
			Expect(k8sClient.DeleteAllOf(ctx, &ep, nsSelector)).Should(Succeed())
			Eventually(func() int {
				svcPorts := svc.ServicePortList{}
				Expect(k8sClient.List(ctx, &svcPorts, nsSelector)).Should(Succeed())
				return len(svcPorts.Items)
			}, time.Minute, interval).Should(BeZero())
		})

		It("add endpoints without portname", func() {
			expectSvcPort := newSvcPort(epNamespacedName, "")
			expectSvcPort.Spec.Backends = []svc.Backend{
				{
					IP:       ip1,
					Protocol: corev1.ProtocolTCP,
					Port:     80,
				}, {
					IP:       ip2,
					Protocol: corev1.ProtocolTCP,
					Port:     80,
					Node:     node2,
				},
			}

			svcPorts := svc.ServicePortList{}
			Eventually(func() bool {
				Expect(k8sClient.List(ctx, &svcPorts, nsSelector)).Should(Succeed())
				if len(svcPorts.Items) != 1 {
					return false
				}
				return svcPorts.Items[0].Equal(expectSvcPort)
			}, time.Minute, interval).Should(BeTrue())
		})

		It("update endpoints without portname", func() {
			newEndpoints := corev1.Endpoints{
				ObjectMeta: metav1.ObjectMeta{
					Name:      epNamespacedName.Name,
					Namespace: epNamespacedName.Namespace,
				},
				Subsets: []corev1.EndpointSubset{
					{
						Addresses: []corev1.EndpointAddress{
							{
								IP:       ip2,
								NodeName: &node2,
							},
						},
						Ports: []corev1.EndpointPort{
							{
								Port:     80,
								Protocol: corev1.ProtocolTCP,
							},
						},
					}, {
						Addresses: []corev1.EndpointAddress{
							{
								IP:       ip1,
								NodeName: &node1,
							},
							{
								IP:       ip3,
								NodeName: &node1,
							},
						},
						Ports: []corev1.EndpointPort{
							{
								Port:     34,
								Protocol: corev1.ProtocolTCP,
							},
						},
					},
				},
			}
			Expect(k8sClient.Update(ctx, &newEndpoints)).Should(Succeed())

			expectSvcPort := newSvcPort(epNamespacedName, "")
			expectSvcPort.Spec.Backends = []svc.Backend{
				{
					IP:       ip1,
					Protocol: corev1.ProtocolTCP,
					Port:     34,
					Node:     node1,
				}, {
					IP:       ip2,
					Protocol: corev1.ProtocolTCP,
					Port:     80,
					Node:     node2,
				}, {
					IP:       ip3,
					Protocol: corev1.ProtocolTCP,
					Port:     34,
					Node:     node1,
				},
			}

			svcPorts := svc.ServicePortList{}
			Eventually(func() bool {
				Expect(k8sClient.List(ctx, &svcPorts, nsSelector)).Should(Succeed())
				if len(svcPorts.Items) != 1 {
					return false
				}
				return svcPorts.Items[0].Equal(expectSvcPort)
			}, time.Minute, interval).Should(BeTrue())
		})

		It("update endpoints with invalid ipv4", func() {
			newEndpoints := corev1.Endpoints{
				ObjectMeta: metav1.ObjectMeta{
					Name:      epNamespacedName.Name,
					Namespace: epNamespacedName.Namespace,
				},
				Subsets: []corev1.EndpointSubset{
					{
						Addresses: []corev1.EndpointAddress{
							{
								IP:       ip2,
								NodeName: &node2,
							},
						},
						Ports: []corev1.EndpointPort{
							{
								Port:     80,
								Protocol: corev1.ProtocolTCP,
							},
						},
					}, {
						Addresses: []corev1.EndpointAddress{
							{
								IP:       "2345::e12",
								NodeName: &node1,
							},
							{
								IP:       ip3,
								NodeName: &node1,
							},
						},
						Ports: []corev1.EndpointPort{
							{
								Port:     34,
								Protocol: corev1.ProtocolTCP,
							},
						},
					},
				},
			}
			Expect(k8sClient.Update(ctx, &newEndpoints)).Should(Succeed())

			expectSvcPort := newSvcPort(epNamespacedName, "")
			expectSvcPort.Spec.Backends = []svc.Backend{
				{
					IP:       ip2,
					Protocol: corev1.ProtocolTCP,
					Port:     80,
					Node:     node2,
				}, {
					IP:       ip3,
					Protocol: corev1.ProtocolTCP,
					Port:     34,
					Node:     node1,
				},
			}

			svcPorts := svc.ServicePortList{}
			Eventually(func() bool {
				Expect(k8sClient.List(ctx, &svcPorts, nsSelector)).Should(Succeed())
				if len(svcPorts.Items) != 1 {
					return false
				}
				return svcPorts.Items[0].Equal(expectSvcPort)
			}, time.Minute, interval).Should(BeTrue())
		})
	})

	Context("endpoints from headless serivce", func() {
		endpoints := corev1.Endpoints{
			ObjectMeta: metav1.ObjectMeta{
				Name:      epNamespacedNameHeadless.Name,
				Namespace: epNamespacedNameHeadless.Namespace,
			},
			Subsets: []corev1.EndpointSubset{
				{
					Addresses: []corev1.EndpointAddress{
						{
							IP: ip1,
						}, {
							IP:       ip2,
							NodeName: &node2,
						},
					},
					Ports: []corev1.EndpointPort{
						{
							Port:     80,
							Protocol: corev1.ProtocolTCP,
						},
					},
				},
			},
		}
		BeforeEach(func() {
			createEndpoints := endpoints
			Expect(k8sClient.Create(ctx, &createEndpoints)).Should(Succeed())
			Eventually(func() error {
				return k8sClient.Get(ctx, epNamespacedNameHeadless, &corev1.Endpoints{})
			}, time.Minute, interval).Should(BeNil())
		})

		AfterEach(func() {
			ep := corev1.Endpoints{}
			Expect(k8sClient.DeleteAllOf(ctx, &ep, nsSelector)).Should(Succeed())
			Eventually(func() int {
				svcPorts := svc.ServicePortList{}
				Expect(k8sClient.List(ctx, &svcPorts, nsSelector)).Should(Succeed())
				return len(svcPorts.Items)
			}, time.Minute, interval).Should(BeZero())
		})

		It("should not create service port", func() {
			Eventually(func() bool {
				err := k8sClient.Get(ctx, epNamespacedNameHeadless, &svc.ServicePort{})
				return errors.IsNotFound(err)
			}, time.Minute, interval).Should(BeTrue())
		})
	})

	Context("endpoints with multi ports", func() {
		endpoints := corev1.Endpoints{
			ObjectMeta: metav1.ObjectMeta{
				Name:      epNamespacedName.Name,
				Namespace: epNamespacedName.Namespace,
			},
			Subsets: []corev1.EndpointSubset{
				{
					Addresses: []corev1.EndpointAddress{
						{
							IP:       ip1,
							NodeName: &node1,
						}, {
							IP:       ip2,
							NodeName: &node2,
						},
					},
					Ports: []corev1.EndpointPort{
						{
							Name:     portName1,
							Port:     80,
							Protocol: corev1.ProtocolTCP,
						}, {
							Name:     portName2,
							Port:     22,
							Protocol: corev1.ProtocolTCP,
						},
					},
				}, {
					Addresses: []corev1.EndpointAddress{
						{
							IP:       ip3,
							NodeName: &node2,
						},
					},
					Ports: []corev1.EndpointPort{
						{
							Name:     portName2,
							Port:     25,
							Protocol: corev1.ProtocolTCP,
						},
					},
				},
			},
		}
		BeforeEach(func() {
			createEndpoints := endpoints
			Expect(k8sClient.Create(ctx, &createEndpoints)).Should(Succeed())
		})

		AfterEach(func() {
			ep := corev1.Endpoints{}
			Expect(k8sClient.DeleteAllOf(ctx, &ep, nsSelector)).Should(Succeed())
			Eventually(func() int {
				svcPorts := svc.ServicePortList{}
				Expect(k8sClient.List(ctx, &svcPorts, nsSelector)).Should(Succeed())
				return len(svcPorts.Items)
			}, time.Minute, interval).Should(BeZero())
		})

		It("add endpoints with multi ports", func() {
			expectSvcPortMap := make(map[string]*svc.ServicePort)
			expectSvcPortMap[portName1] = newSvcPort(epNamespacedName, portName1)
			expectSvcPortMap[portName1].Spec.Backends = []svc.Backend{
				{
					IP:       ip1,
					Node:     node1,
					Port:     80,
					Protocol: corev1.ProtocolTCP,
				}, {
					IP:       ip2,
					Node:     node2,
					Port:     80,
					Protocol: corev1.ProtocolTCP,
				},
			}
			expectSvcPortMap[portName2] = newSvcPort(epNamespacedName, portName2)
			expectSvcPortMap[portName2].Spec.Backends = []svc.Backend{
				{
					IP:       ip1,
					Node:     node1,
					Port:     22,
					Protocol: corev1.ProtocolTCP,
				}, {
					IP:       ip2,
					Node:     node2,
					Port:     22,
					Protocol: corev1.ProtocolTCP,
				}, {
					IP:       ip3,
					Node:     node2,
					Port:     25,
					Protocol: corev1.ProtocolTCP,
				},
			}

			svcPorts := svc.ServicePortList{}
			Eventually(func() bool {
				Expect(k8sClient.List(ctx, &svcPorts, nsSelector)).Should(Succeed())
				if len(svcPorts.Items) != 2 {
					return false
				}
				svcPortMap := servicePortListToServicePortMap(svcPorts)
				return svcPortMap[portName1].Equal(expectSvcPortMap[portName1]) && svcPortMap[portName2].Equal(expectSvcPortMap[portName2])
			}, time.Minute, interval).Should(BeTrue())
		})

		It("update endpoints with multi ports", func() {
			newEndpoints := corev1.Endpoints{
				ObjectMeta: metav1.ObjectMeta{
					Name:      epNamespacedName.Name,
					Namespace: epNamespacedName.Namespace,
				},
				Subsets: []corev1.EndpointSubset{
					{
						Addresses: []corev1.EndpointAddress{
							{
								IP:       ip1,
								NodeName: &node1,
							},
						},
						Ports: []corev1.EndpointPort{
							{
								Name:     portName2,
								Port:     22,
								Protocol: corev1.ProtocolTCP,
							},
						},
					}, {
						Addresses: []corev1.EndpointAddress{
							{
								IP:       ip3,
								NodeName: &node2,
							},
						},
						Ports: []corev1.EndpointPort{
							{
								Name:     portName2,
								Port:     25,
								Protocol: corev1.ProtocolTCP,
							},
						},
					},
				},
			}
			Expect(k8sClient.Update(ctx, &newEndpoints)).Should(Succeed())

			expectSvcPort := newSvcPort(epNamespacedName, portName2)
			expectSvcPort.Spec.Backends = []svc.Backend{
				{
					IP:       ip1,
					Node:     node1,
					Port:     22,
					Protocol: corev1.ProtocolTCP,
				}, {
					IP:       ip3,
					Node:     node2,
					Port:     25,
					Protocol: corev1.ProtocolTCP,
				},
			}

			svcPorts := svc.ServicePortList{}
			Eventually(func() bool {
				Expect(k8sClient.List(ctx, &svcPorts, nsSelector)).Should(Succeed())
				if len(svcPorts.Items) != 1 {
					return false
				}
				return svcPorts.Items[0].Equal(expectSvcPort)
			}, time.Minute, interval).Should(BeTrue())
		})
	})
})
