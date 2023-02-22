package proxy

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	proxycache "github.com/everoute/everoute/pkg/agent/controller/proxy/cache"
)

var _ = Describe("proxy controller", func() {
	ctx := context.Background()
	svcName := "svc1"
	svcNs := "default"
	svcID := proxycache.GenSvcID(svcNs, svcName)
	ip1 := "10.0.0.12"
	port1 := proxycache.Port{
		Name:     "dhcp",
		NodePort: 30601,
		Protocol: corev1.ProtocolUDP,
		Port:     56,
	}
	port2 := proxycache.Port{
		Name:     "ssh",
		Protocol: corev1.ProtocolTCP,
		Port:     22,
	}
	port3 := proxycache.Port{
		Name:     "http",
		Protocol: corev1.ProtocolTCP,
		Port:     80,
	}
	affinityTimeout := int32(100)
	ipFamilyPolicy := corev1.IPFamilyPolicySingleStack

	Context("test add service", func() {
		svc := corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      svcName,
				Namespace: svcNs,
			},
			Spec: corev1.ServiceSpec{
				Type:            corev1.ServiceTypeNodePort,
				ClusterIP:       ip1,
				ClusterIPs:      []string{ip1},
				SessionAffinity: corev1.ServiceAffinityNone,
				Ports: []corev1.ServicePort{
					{
						Name:     port1.Name,
						NodePort: port1.NodePort,
						Protocol: port1.Protocol,
						Port:     port1.Port,
					},
				},
				IPFamilyPolicy: &ipFamilyPolicy,
				IPFamilies:     []corev1.IPFamily{corev1.IPv4Protocol},
			},
		}

		AfterEach(func() {
			Expect(k8sClient.Delete(ctx, &svc)).Should(Succeed())
			Eventually(func() bool {
				_, exists, _ := proxyController.baseSvcCache.GetByKey(svcID)
				return !exists
			}, Timeout, Interval).Should(BeTrue())
			dpOvs := svcIndex.GetSvcOvsInfo(svcID)
			Expect(dpOvs).Should(BeNil())
		})

		It("add service normal", func() {
			svcCopy := svc.DeepCopy()
			Expect(k8sClient.Create(ctx, svcCopy)).Should(Succeed())

			expBaseSvc := proxycache.BaseSvc{
				SvcID:      svcNs + "/" + svcName,
				SvcType:    corev1.ServiceTypeNodePort,
				ClusterIPs: []string{ip1},
				Ports: map[string]*proxycache.Port{
					port1.Name: &port1,
				},
				SessionAffinity: corev1.ServiceAffinityNone,
			}
			Eventually(func() bool {
				obj, _, _ := proxyController.baseSvcCache.GetByKey(svcID)
				if obj == nil {
					return false
				}
				return equalBaseSvc(&expBaseSvc, obj.(*proxycache.BaseSvc))
			}, Timeout, Interval).Should(BeTrue())
			dpOvs := svcIndex.GetSvcOvsInfo(svcID)
			Expect(dpOvs).ShouldNot(BeNil())
			Expect(dpOvs.GetLBFlow(ip1, port1.Name)).ShouldNot(BeNil())
			Expect(dpOvs.GetGroup(port1.Name)).ShouldNot(BeNil())
		})

		It("add service with session affinity", func() {
			svcCopy := svc.DeepCopy()
			svcCopy.Spec.SessionAffinity = corev1.ServiceAffinityClientIP
			svcCopy.Spec.SessionAffinityConfig = &corev1.SessionAffinityConfig{
				ClientIP: &corev1.ClientIPConfig{TimeoutSeconds: &affinityTimeout},
			}
			Expect(k8sClient.Create(ctx, svcCopy)).Should(Succeed())
			expBaseSvc := proxycache.BaseSvc{
				SvcID:      svcNs + "/" + svcName,
				SvcType:    corev1.ServiceTypeNodePort,
				ClusterIPs: []string{ip1},
				Ports: map[string]*proxycache.Port{
					port1.Name: &port1,
				},
				SessionAffinity:        corev1.ServiceAffinityClientIP,
				SessionAffinityTimeout: affinityTimeout,
			}
			Eventually(func() bool {
				obj, _, _ := proxyController.baseSvcCache.GetByKey(svcID)
				if obj == nil {
					return false
				}
				return equalBaseSvc(&expBaseSvc, obj.(*proxycache.BaseSvc))
			}, Timeout, Interval).Should(BeTrue())
			dpOvs := svcIndex.GetSvcOvsInfo(svcID)
			Expect(dpOvs).ShouldNot(BeNil())
			Expect(dpOvs.GetLBFlow(ip1, port1.Name)).ShouldNot(BeNil())
			Expect(dpOvs.GetGroup(port1.Name)).ShouldNot(BeNil())
			Expect(dpOvs.GetSessionAffinityFlow(ip1, port1.Name)).ShouldNot(BeNil())
		})

		It("add headless service", func() {
			svcCopy := svc.DeepCopy()
			svcCopy.Spec.Type = corev1.ServiceTypeClusterIP
			svcCopy.Spec.ClusterIP = "None"
			svcCopy.Spec.ClusterIPs = []string{"None"}
			svcCopy.Spec.Ports = []corev1.ServicePort{
				{
					Name:     port2.Name,
					Protocol: port2.Protocol,
					Port:     port2.Port,
				},
			}
			Expect(k8sClient.Create(ctx, svcCopy)).Should(Succeed())
			time.Sleep(Timeout)
			_, exists, _ := proxyController.baseSvcCache.GetByKey(svcID)
			Expect(exists).Should(BeFalse())
			Expect(svcIndex.GetSvcOvsInfo(svcID)).Should(BeNil())
		})

		It("add ExternalName service", func() {
			svcCopy := svc.DeepCopy()
			svcCopy.Spec.Type = corev1.ServiceTypeExternalName
			svcCopy.Spec.ClusterIP = ""
			svcCopy.Spec.ClusterIPs = []string{}
			svcCopy.Spec.ExternalName = "test"
			Expect(k8sClient.Create(ctx, svcCopy)).Should(Succeed())
			time.Sleep(Timeout)
			_, exists, _ := proxyController.baseSvcCache.GetByKey(svcID)
			Expect(exists).Should(BeFalse())
			Expect(svcIndex.GetSvcOvsInfo(svcID)).Should(BeNil())
		})
	})

	Context("test update service", func() {
		svc := corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      svcName,
				Namespace: svcNs,
			},
			Spec: corev1.ServiceSpec{
				Type:       corev1.ServiceTypeNodePort,
				ClusterIP:  ip1,
				ClusterIPs: []string{ip1},
				Ports: []corev1.ServicePort{
					{
						Name:     port1.Name,
						NodePort: port1.NodePort,
						Protocol: port1.Protocol,
						Port:     port1.Port,
					},
					{
						Name:     port2.Name,
						NodePort: port2.NodePort,
						Protocol: port2.Protocol,
						Port:     port2.Port,
					},
				},
				SessionAffinity: corev1.ServiceAffinityClientIP,
				SessionAffinityConfig: &corev1.SessionAffinityConfig{
					ClientIP: &corev1.ClientIPConfig{TimeoutSeconds: &affinityTimeout},
				},
			},
		}
		var oldOvsInfo *testSvcOvsInfo
		var svcCopy corev1.Service
		BeforeEach(func() {
			svcCopy = svc
			Expect(k8sClient.Create(ctx, &svcCopy)).Should(Succeed())
			expBaseSvc := proxycache.BaseSvc{
				SvcID:      svcNs + "/" + svcName,
				SvcType:    corev1.ServiceTypeNodePort,
				ClusterIPs: []string{ip1},
				Ports: map[string]*proxycache.Port{
					port1.Name: &port1,
					port2.Name: &port2,
				},
				SessionAffinity:        corev1.ServiceAffinityClientIP,
				SessionAffinityTimeout: affinityTimeout,
			}
			Eventually(func() bool {
				obj, _, _ := proxyController.baseSvcCache.GetByKey(svcID)
				if obj == nil {
					return false
				}
				return equalBaseSvc(&expBaseSvc, obj.(*proxycache.BaseSvc))
			}, Timeout, Interval).Should(BeTrue())
			dpOvs := svcIndex.GetSvcOvsInfo(svcID)
			Expect(dpOvs).ShouldNot(BeNil())
			for _, portName := range []string{port1.Name, port2.Name} {
				Expect(dpOvs.GetLBFlow(ip1, portName)).ShouldNot(BeNil())
				Expect(dpOvs.GetGroup(portName)).ShouldNot(BeNil())
				Expect(dpOvs.GetSessionAffinityFlow(ip1, portName)).ShouldNot(BeNil())
			}
			oldOvsInfo = genTestSvcOvsInfo(dpOvs)
		})

		AfterEach(func() {
			Expect(k8sClient.Delete(ctx, &svc)).Should(Succeed())
			Eventually(func() bool {
				_, exists, _ := proxyController.baseSvcCache.GetByKey(svcID)
				return !exists
			}, Timeout, Interval).Should(BeTrue())
			Expect(svcIndex.GetSvcOvsInfo(svcID)).Should(BeNil())
		})

		It("add a service port with protocol support", func() {
			newService := svcCopy
			newService.Spec.Ports = append(newService.Spec.Ports, corev1.ServicePort{
				Name:     port3.Name,
				NodePort: port3.NodePort,
				Protocol: port3.Protocol,
				Port:     port3.Port,
			})
			Expect(k8sClient.Update(ctx, &newService)).Should(Succeed())
			expBaseSvc := proxycache.BaseSvc{
				SvcID:      svcNs + "/" + svcName,
				SvcType:    corev1.ServiceTypeNodePort,
				ClusterIPs: []string{ip1},
				Ports: map[string]*proxycache.Port{
					port1.Name: &port1,
					port2.Name: &port2,
					port3.Name: &port3,
				},
				SessionAffinity:        corev1.ServiceAffinityClientIP,
				SessionAffinityTimeout: affinityTimeout,
			}
			Eventually(func() bool {
				obj, _, _ := proxyController.baseSvcCache.GetByKey(svcID)
				if obj == nil {
					return false
				}
				return equalBaseSvc(&expBaseSvc, obj.(*proxycache.BaseSvc))
			}, Timeout, Interval).Should(BeTrue())
			dpOvs := svcIndex.GetSvcOvsInfo(svcID)
			Expect(dpOvs).ShouldNot(BeNil())
			for _, portName := range []string{port1.Name, port2.Name} {
				Expect(dpOvs.GetLBFlow(ip1, portName).FlowID).Should(Equal(oldOvsInfo.lbMap[ip1][portName]))
				Expect(dpOvs.GetGroup(portName).GroupID).Should(Equal(oldOvsInfo.groupMap[portName]))
				Expect(dpOvs.GetSessionAffinityFlow(ip1, portName).FlowID).Should(Equal(oldOvsInfo.sessionAffinityMap[ip1][portName]))
			}
			Expect(dpOvs.GetLBFlow(ip1, port3.Name)).ShouldNot(BeNil())
			Expect(dpOvs.GetGroup(port3.Name)).ShouldNot(BeNil())
			Expect(dpOvs.GetSessionAffinityFlow(ip1, port3.Name)).ShouldNot(BeNil())
		})

		It("delete service port", func() {
			newService := svcCopy
			newService.Spec.Ports = []corev1.ServicePort{
				{
					Name:     port1.Name,
					NodePort: port1.NodePort,
					Protocol: port1.Protocol,
					Port:     port1.Port,
				},
			}
			Expect(k8sClient.Update(ctx, &newService)).Should(Succeed())
			expBaseSvc := proxycache.BaseSvc{
				SvcID:      svcNs + "/" + svcName,
				SvcType:    corev1.ServiceTypeNodePort,
				ClusterIPs: []string{ip1},
				Ports: map[string]*proxycache.Port{
					port1.Name: &port1,
				},
				SessionAffinity:        corev1.ServiceAffinityClientIP,
				SessionAffinityTimeout: affinityTimeout,
			}
			Eventually(func() bool {
				obj, _, _ := proxyController.baseSvcCache.GetByKey(svcID)
				if obj == nil {
					return false
				}
				return equalBaseSvc(&expBaseSvc, obj.(*proxycache.BaseSvc))
			}, Timeout, Interval).Should(BeTrue())
			dpOvs := svcIndex.GetSvcOvsInfo(svcID)
			Expect(dpOvs).ShouldNot(BeNil())
			for _, portName := range []string{port1.Name} {
				Expect(dpOvs.GetLBFlow(ip1, portName).FlowID).Should(Equal(oldOvsInfo.lbMap[ip1][portName]))
				Expect(dpOvs.GetGroup(portName).GroupID).Should(Equal(oldOvsInfo.groupMap[portName]))
				Expect(dpOvs.GetSessionAffinityFlow(ip1, portName).FlowID).Should(Equal(oldOvsInfo.sessionAffinityMap[ip1][portName]))
			}
			Expect(dpOvs.GetLBFlow(ip1, port2.Name)).Should(BeNil())
			Expect(dpOvs.GetGroup(port2.Name)).Should(BeNil())
			Expect(dpOvs.GetSessionAffinityFlow(ip1, port2.Name)).Should(BeNil())
		})

		It("change service port", func() {
			newService := svcCopy
			updatePort2 := proxycache.Port{
				Name:     port2.Name,
				NodePort: port2.NodePort,
				Protocol: port2.Protocol,
				Port:     1000,
			}
			newService.Spec.Ports = []corev1.ServicePort{
				{
					Name:     port1.Name,
					NodePort: port1.NodePort,
					Protocol: port1.Protocol,
					Port:     port1.Port,
				},
				{
					Name:     port2.Name,
					NodePort: port2.NodePort,
					Protocol: port2.Protocol,
					Port:     updatePort2.Port,
				},
			}
			Expect(k8sClient.Update(ctx, &newService)).Should(Succeed())
			expBaseSvc := proxycache.BaseSvc{
				SvcID:      svcNs + "/" + svcName,
				SvcType:    corev1.ServiceTypeNodePort,
				ClusterIPs: []string{ip1},
				Ports: map[string]*proxycache.Port{
					port1.Name: &port1,
					port2.Name: &updatePort2,
				},
				SessionAffinity:        corev1.ServiceAffinityClientIP,
				SessionAffinityTimeout: affinityTimeout,
			}
			Eventually(func() bool {
				obj, _, _ := proxyController.baseSvcCache.GetByKey(svcID)
				if obj == nil {
					return false
				}
				return equalBaseSvc(&expBaseSvc, obj.(*proxycache.BaseSvc))
			}, Timeout, Interval).Should(BeTrue())
			dpOvs := svcIndex.GetSvcOvsInfo(svcID)
			Expect(dpOvs).ShouldNot(BeNil())
			for _, portName := range []string{port1.Name} {
				Expect(dpOvs.GetLBFlow(ip1, portName).FlowID).Should(Equal(oldOvsInfo.lbMap[ip1][portName]))
				Expect(dpOvs.GetGroup(portName).GroupID).Should(Equal(oldOvsInfo.groupMap[portName]))
				Expect(dpOvs.GetSessionAffinityFlow(ip1, portName).FlowID).Should(Equal(oldOvsInfo.sessionAffinityMap[ip1][portName]))
			}
			// group not change
			Expect(dpOvs.GetGroup(port2.Name).GroupID).Should(Equal(oldOvsInfo.groupMap[port2.Name]))

			// flow should change
			Expect(dpOvs.GetLBFlow(ip1, port2.Name).FlowID).ShouldNot(Equal(oldOvsInfo.lbMap[ip1][port2.Name]))
			Expect(dpOvs.GetSessionAffinityFlow(ip1, port2.Name).FlowID).ShouldNot(Equal(oldOvsInfo.sessionAffinityMap[ip1][port2.Name]))
		})

		It("change session affinity mode", func() {
			By("session affinity change from clientip to none")
			newService := svcCopy
			newService.Spec.SessionAffinity = corev1.ServiceAffinityNone
			newService.Spec.SessionAffinityConfig = nil
			Expect(k8sClient.Update(ctx, &newService)).Should(Succeed())
			expBaseSvc := proxycache.BaseSvc{
				SvcID:      svcNs + "/" + svcName,
				SvcType:    corev1.ServiceTypeNodePort,
				ClusterIPs: []string{ip1},
				Ports: map[string]*proxycache.Port{
					port1.Name: &port1,
					port2.Name: &port2,
				},
				SessionAffinity: corev1.ServiceAffinityNone,
			}
			Eventually(func() bool {
				obj, _, _ := proxyController.baseSvcCache.GetByKey(svcID)
				if obj == nil {
					return false
				}
				return equalBaseSvc(&expBaseSvc, obj.(*proxycache.BaseSvc))
			}, Timeout, Interval).Should(BeTrue())
			dpOvs := svcIndex.GetSvcOvsInfo(svcID)
			Expect(dpOvs).ShouldNot(BeNil())
			for _, portName := range []string{port1.Name, port2.Name} {
				Expect(dpOvs.GetLBFlow(ip1, portName).FlowID).Should(Equal(oldOvsInfo.lbMap[ip1][portName]))
				Expect(dpOvs.GetGroup(portName).GroupID).Should(Equal(oldOvsInfo.groupMap[portName]))
			}
			Expect(len(dpOvs.GetAllSessionAffinityFlows())).Should(BeZero())

			By("session affinity change from node to clientip, and session affinity config is default")
			newService2 := newService
			newService2.Spec.SessionAffinity = corev1.ServiceAffinityClientIP
			newService2.Spec.SessionAffinityConfig = &corev1.SessionAffinityConfig{ClientIP: nil}
			Expect(k8sClient.Update(ctx, &newService2)).Should(Succeed())
			expBaseSvc2 := proxycache.BaseSvc{
				SvcID:      svcNs + "/" + svcName,
				SvcType:    corev1.ServiceTypeNodePort,
				ClusterIPs: []string{ip1},
				Ports: map[string]*proxycache.Port{
					port1.Name: &port1,
					port2.Name: &port2,
				},
				SessionAffinity:        corev1.ServiceAffinityClientIP,
				SessionAffinityTimeout: proxycache.DefaultSessionAffinityTimeout,
			}
			Eventually(func() bool {
				obj, _, _ := proxyController.baseSvcCache.GetByKey(svcID)
				if obj == nil {
					return false
				}
				return equalBaseSvc(&expBaseSvc2, obj.(*proxycache.BaseSvc))
			}, Timeout, Interval).Should(BeTrue())
			dpOvs = svcIndex.GetSvcOvsInfo(svcID)
			Expect(dpOvs).ShouldNot(BeNil())
			for _, portName := range []string{port1.Name, port2.Name} {
				Expect(dpOvs.GetLBFlow(ip1, portName).FlowID).Should(Equal(oldOvsInfo.lbMap[ip1][portName]))
				Expect(dpOvs.GetGroup(portName).GroupID).Should(Equal(oldOvsInfo.groupMap[portName]))
				Expect(dpOvs.GetSessionAffinityFlow(ip1, portName).FlowID).ShouldNot(Equal(oldOvsInfo.sessionAffinityMap[ip1][portName]))
			}
		})

		It("change session affinity timeout", func() {
			newService := svcCopy
			newTimeout := int32(5000)
			newService.Spec.SessionAffinityConfig.ClientIP.TimeoutSeconds = &newTimeout
			Expect(k8sClient.Update(ctx, &newService)).Should(Succeed())
			expBaseSvc := proxycache.BaseSvc{
				SvcID:      svcNs + "/" + svcName,
				SvcType:    corev1.ServiceTypeNodePort,
				ClusterIPs: []string{ip1},
				Ports: map[string]*proxycache.Port{
					port1.Name: &port1,
					port2.Name: &port2,
				},
				SessionAffinity:        corev1.ServiceAffinityClientIP,
				SessionAffinityTimeout: newTimeout,
			}
			Eventually(func() bool {
				obj, _, _ := proxyController.baseSvcCache.GetByKey(svcID)
				if obj == nil {
					return false
				}
				return equalBaseSvc(&expBaseSvc, obj.(*proxycache.BaseSvc))
			}, Timeout, Interval).Should(BeTrue())
			dpOvs := svcIndex.GetSvcOvsInfo(svcID)
			Expect(dpOvs).ShouldNot(BeNil())
			for _, portName := range []string{port1.Name, port2.Name} {
				Expect(dpOvs.GetLBFlow(ip1, portName).FlowID).Should(Equal(oldOvsInfo.lbMap[ip1][portName]))
				Expect(dpOvs.GetGroup(portName).GroupID).Should(Equal(oldOvsInfo.groupMap[portName]))
				Expect(dpOvs.GetSessionAffinityFlow(ip1, portName).FlowID).ShouldNot(Equal(oldOvsInfo.sessionAffinityMap[ip1][portName]))
			}
		})
	})
})
