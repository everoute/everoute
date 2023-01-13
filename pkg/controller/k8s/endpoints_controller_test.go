package k8s

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	svc "github.com/everoute/everoute/pkg/apis/service/v1alpha1"
)

var _ = Describe("endpoints controller", func() {
	ctx := context.Background()
	epNamespacedName := types.NamespacedName{
		Name:      "eps",
		Namespace: "default",
	}
	node1 := "node1"
	node2 := "node2"
	ip1 := "10.0.0.3"
	ip2 := "10.0.0.4"
	ip3 := "10.0.0.5"
	portName1 := "http"
	portName2 := "ssh"

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
			Expect(k8sClient.Delete(ctx, &endpoints)).Should(Succeed())
			Eventually(func() int {
				eps := corev1.EndpointsList{}
				Expect(k8sClient.List(ctx, &eps)).Should(Succeed())
				return len(eps.Items)
			}, time.Minute, interval).Should(BeZero())
			Eventually(func() int {
				svcPorts := svc.ServicePortList{}
				Expect(k8sClient.List(ctx, &svcPorts)).Should(Succeed())
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
				Expect(k8sClient.List(ctx, &svcPorts)).Should(Succeed())
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
				Expect(k8sClient.List(ctx, &svcPorts)).Should(Succeed())
				if len(svcPorts.Items) != 1 {
					return false
				}
				return svcPorts.Items[0].Equal(expectSvcPort)
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
			Expect(k8sClient.Delete(ctx, &endpoints)).Should(Succeed())
			Eventually(func() int {
				eps := corev1.EndpointsList{}
				Expect(k8sClient.List(ctx, &eps)).Should(Succeed())
				return len(eps.Items)
			}, time.Minute, interval).Should(BeZero())
			Eventually(func() int {
				svcPorts := svc.ServicePortList{}
				Expect(k8sClient.List(ctx, &svcPorts)).Should(Succeed())
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
				Expect(k8sClient.List(ctx, &svcPorts)).Should(Succeed())
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
				Expect(k8sClient.List(ctx, &svcPorts)).Should(Succeed())
				if len(svcPorts.Items) != 1 {
					return false
				}
				return svcPorts.Items[0].Equal(expectSvcPort)
			}, time.Minute, interval).Should(BeTrue())
		})
	})
})
