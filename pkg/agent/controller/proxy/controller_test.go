package proxy

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"

	proxycache "github.com/everoute/everoute/pkg/agent/controller/proxy/cache"
	everoutesvc "github.com/everoute/everoute/pkg/apis/service/v1alpha1"
	ersource "github.com/everoute/everoute/pkg/source"
	ertype "github.com/everoute/everoute/pkg/types"
)

var _ = Describe("proxy controller", func() {
	ctx := context.Background()
	var (
		svcNs    = "default"
		svcName  = "svc1"
		svcName2 = "svc2"
		svcID    = proxycache.GenSvcID(svcNs, svcName)
		svcID2   = proxycache.GenSvcID(svcNs, svcName2)

		ip1             = "10.0.0.12"
		ip2             = "10.3.4.5"
		ip3             = "123.1.1.1"
		affinityTimeout = int32(100)
		ipFamilyPolicy  = corev1.IPFamilyPolicySingleStack
	)

	var (
		port1 = proxycache.Port{
			Name:     "dhcp",
			NodePort: 30601,
			Protocol: corev1.ProtocolUDP,
			Port:     56,
		}
		portName1    = port1.Name
		svcPortName1 = "svcportname-dhcp"

		port2 = proxycache.Port{
			Name:     "ssh",
			Protocol: corev1.ProtocolTCP,
			Port:     22,
		}
		portName2    = port2.Name
		svcPortName2 = "svcportname-ssh"

		port3 = proxycache.Port{
			Name:     "http",
			Protocol: corev1.ProtocolTCP,
			Port:     80,
		}
		portName3 = port3.Name
	)

	var (
		backend1 = everoutesvc.Backend{
			IP:       "10.244.0.1",
			Protocol: corev1.ProtocolTCP,
			Port:     788,
			Node:     localNode,
		}
		bk1 = proxycache.GenBackendKey(backend1.IP, backend1.Port, backend1.Protocol)

		backend2 = everoutesvc.Backend{
			IP:       "10.244.2.1",
			Protocol: corev1.ProtocolUDP,
			Port:     78,
			Node:     "node1",
		}
		bk2 = proxycache.GenBackendKey(backend2.IP, backend2.Port, backend2.Protocol)

		backend3 = everoutesvc.Backend{
			IP:       backend1.IP,
			Protocol: backend1.Protocol,
			Port:     123,
			Node:     "node1",
		}
		bk3 = proxycache.GenBackendKey(backend3.IP, backend3.Port, backend3.Protocol)
	)

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
			Expect(dpOvs.GetGroup(port1.Name, ertype.TrafficPolicyCluster)).ShouldNot(BeNil())
			Expect(dpOvs.GetGroup(port1.Name, ertype.TrafficPolicyLocal)).Should(BeNil())
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
			Expect(dpOvs.GetGroup(port1.Name, ertype.TrafficPolicyCluster)).ShouldNot(BeNil())
			Expect(dpOvs.GetGroup(port1.Name, ertype.TrafficPolicyLocal)).Should(BeNil())
			Expect(dpOvs.GetSessionAffinityFlow(ip1, port1.Name)).ShouldNot(BeNil())
		})
		It("add service with traffic policy local", func() {
			svcCopy := svc.DeepCopy()
			svcCopy.Spec.SessionAffinity = corev1.ServiceAffinityClientIP
			svcCopy.Spec.SessionAffinityConfig = &corev1.SessionAffinityConfig{
				ClientIP: &corev1.ClientIPConfig{TimeoutSeconds: &affinityTimeout},
			}
			tp := corev1.ServiceInternalTrafficPolicyLocal
			svcCopy.Spec.InternalTrafficPolicy = &tp
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
				InternalTrafficPolicy:  ertype.TrafficPolicyLocal,
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
			Expect(dpOvs.GetGroup(port1.Name, ertype.TrafficPolicyCluster)).Should(BeNil())
			Expect(dpOvs.GetGroup(port1.Name, ertype.TrafficPolicyLocal)).ShouldNot(BeNil())
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
			time.Sleep(10 * time.Second)
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
			svcCopy.Spec.IPFamilies = nil
			svcCopy.Spec.IPFamilyPolicy = nil
			Expect(k8sClient.Create(ctx, svcCopy)).Should(Succeed())
			time.Sleep(10 * time.Second)
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
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyCluster)).ShouldNot(BeNil())
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyLocal)).Should(BeNil())
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
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyCluster).GroupID).Should(Equal(oldOvsInfo.groupMap[portName][ertype.TrafficPolicyCluster]))
				Expect(dpOvs.GetSessionAffinityFlow(ip1, portName).FlowID).Should(Equal(oldOvsInfo.sessionAffinityMap[ip1][portName]))
			}
			Expect(dpOvs.GetLBFlow(ip1, port3.Name)).ShouldNot(BeNil())
			Expect(dpOvs.GetGroup(port3.Name, ertype.TrafficPolicyCluster)).ShouldNot(BeNil())
			Expect(dpOvs.GetGroup(port3.Name, ertype.TrafficPolicyLocal)).Should(BeNil())
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
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyCluster).GroupID).Should(Equal(oldOvsInfo.groupMap[portName][ertype.TrafficPolicyCluster]))
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyLocal)).Should(BeNil())
				Expect(dpOvs.GetSessionAffinityFlow(ip1, portName).FlowID).Should(Equal(oldOvsInfo.sessionAffinityMap[ip1][portName]))
			}
			Expect(dpOvs.GetLBFlow(ip1, port2.Name)).Should(BeNil())
			Expect(dpOvs.GetGroup(port2.Name, ertype.TrafficPolicyCluster)).Should(BeNil())
			Expect(dpOvs.GetGroup(port2.Name, ertype.TrafficPolicyLocal)).Should(BeNil())
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
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyCluster).GroupID).Should(Equal(oldOvsInfo.groupMap[portName][ertype.TrafficPolicyCluster]))
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyLocal)).Should(BeNil())
				Expect(dpOvs.GetSessionAffinityFlow(ip1, portName).FlowID).Should(Equal(oldOvsInfo.sessionAffinityMap[ip1][portName]))
			}
			// group not change
			Expect(dpOvs.GetGroup(port2.Name, ertype.TrafficPolicyCluster).GroupID).Should(Equal(oldOvsInfo.groupMap[port2.Name][ertype.TrafficPolicyCluster]))
			Expect(dpOvs.GetGroup(port2.Name, ertype.TrafficPolicyLocal)).Should(BeNil())

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
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyCluster).GroupID).Should(Equal(oldOvsInfo.groupMap[portName][ertype.TrafficPolicyCluster]))
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyLocal)).Should(BeNil())
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
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyCluster).GroupID).Should(Equal(oldOvsInfo.groupMap[portName][ertype.TrafficPolicyCluster]))
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyLocal)).Should(BeNil())
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
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyCluster).GroupID).Should(Equal(oldOvsInfo.groupMap[portName][ertype.TrafficPolicyCluster]))
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyLocal)).Should(BeNil())
				Expect(dpOvs.GetSessionAffinityFlow(ip1, portName).FlowID).ShouldNot(Equal(oldOvsInfo.sessionAffinityMap[ip1][portName]))
			}
		})

		It("change InternalTrafficPolicy", func() {
			newService := svcCopy
			tp := corev1.ServiceInternalTrafficPolicyLocal
			newService.Spec.InternalTrafficPolicy = &tp
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
				SessionAffinityTimeout: affinityTimeout,
				InternalTrafficPolicy:  ertype.TrafficPolicyLocal,
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
				Expect(dpOvs.GetLBFlow(ip1, portName).FlowID).ShouldNot(Equal(oldOvsInfo.lbMap[ip1][portName]))
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyCluster).GroupID).Should(Equal(oldOvsInfo.groupMap[portName][ertype.TrafficPolicyCluster]))
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyLocal)).ShouldNot(BeNil())
				Expect(dpOvs.GetSessionAffinityFlow(ip1, portName).FlowID).Should(Equal(oldOvsInfo.sessionAffinityMap[ip1][portName]))
			}
		})
	})

	Context("test servicePort without service", func() {
		svcPort := everoutesvc.ServicePort{
			ObjectMeta: metav1.ObjectMeta{
				Name:      svcPortName1,
				Namespace: svcNs,
				Labels:    map[string]string{everoutesvc.LabelRefEndpoints: svcName},
			},
			Spec: everoutesvc.ServicePortSpec{
				PortName: portName1,
				SvcRef:   svcName,
				Backends: []everoutesvc.Backend{backend1},
			},
		}

		var svcPortCopy everoutesvc.ServicePort
		var oldDnatMap map[string]uint64
		BeforeEach(func() {
			svcPortCopy = svcPort
			Expect(k8sClient.Create(ctx, &svcPortCopy)).Should(Succeed())
			expSvcPort := proxycache.SvcPort{
				Name:      svcPortName1,
				Namespace: svcNs,
				PortName:  portName1,
				SvcName:   svcName,
			}
			backendKey := proxycache.GenBackendKey(backend1.IP, backend1.Port, backend1.Protocol)
			svcPortRef := proxycache.GenServicePortRef(svcNs, svcName, portName1)
			expBackend := proxycache.Backend{
				IP:              backend1.IP,
				Protocol:        backend1.Protocol,
				Port:            backend1.Port,
				Node:            backend1.Node,
				ServicePortRefs: sets.NewString(svcPortRef),
			}
			Eventually(func() proxycache.SvcPort {
				svcPortCache, exists, _ := proxyController.svcPortCache.GetByKey(proxycache.GenSvcPortKey(svcNs, svcPortName1))
				if !exists || svcPortCache == nil {
					return proxycache.SvcPort{}
				}
				return *(svcPortCache.(*proxycache.SvcPort))
			}, Timeout, Interval).Should(Equal(expSvcPort))

			Eventually(func() bool {
				backCache, exists, _ := proxyController.backendCache.GetByKey(backendKey)
				if !exists || backCache == nil {
					return false
				}
				return equalBackend(backCache.(*proxycache.Backend), &expBackend)
			}, Timeout, Interval).Should(BeTrue())

			Eventually(func(g Gomega) {
				g.Expect(svcIndex.GetSvcOvsInfo(svcID)).Should(BeNil())
				g.Expect(svcIndex.GetDnatFlow(bk1)).ShouldNot(BeNil())
			}, Timeout, Interval).Should(Succeed())
			oldDnatMap = make(map[string]uint64)
			oldDnatMap[bk1] = svcIndex.GetDnatFlow(bk1).FlowID
		})

		AfterEach(func() {
			delSvcPort := everoutesvc.ServicePort{}
			namespaceSelector := client.InNamespace(svcNs)
			labelSelector := client.MatchingLabels{everoutesvc.LabelRefEndpoints: svcName}
			Expect(k8sClient.DeleteAllOf(ctx, &delSvcPort, namespaceSelector, labelSelector)).Should(Succeed())
			Eventually(func(g Gomega) {
				g.Expect(len(proxyController.svcPortCache.List())).Should(BeZero())
				g.Expect(len(proxyController.backendCache.List())).Should(BeZero())
				g.Expect(svcIndex.GetSvcOvsInfo(svcID)).To(BeNil())
				g.Expect(svcIndex.GetDnatFlow(bk1)).To(BeNil())
				g.Expect(svcIndex.GetDnatFlow(bk2)).To(BeNil())
			}, Timeout, Interval).Should(Succeed())
		})

		It("add a new servicePort with exists backend", func() {
			svcPort2 := everoutesvc.ServicePort{
				ObjectMeta: metav1.ObjectMeta{
					Name:      svcPortName2,
					Namespace: svcNs,
					Labels:    map[string]string{everoutesvc.LabelRefEndpoints: svcName},
				},
				Spec: everoutesvc.ServicePortSpec{
					PortName: portName2,
					SvcRef:   svcName,
					Backends: []everoutesvc.Backend{backend1},
				},
			}
			Expect(k8sClient.Create(ctx, &svcPort2)).Should(Succeed())
			expSvcPort := proxycache.SvcPort{
				Name:      svcPortName2,
				Namespace: svcNs,
				PortName:  portName2,
				SvcName:   svcName,
			}
			backendKey := proxycache.GenBackendKey(backend1.IP, backend1.Port, backend1.Protocol)
			svcPortRef1 := proxycache.GenServicePortRef(svcNs, svcName, portName1)
			svcPortRef2 := proxycache.GenServicePortRef(svcNs, svcName, portName2)
			expBackend := proxycache.Backend{
				IP:              backend1.IP,
				Protocol:        backend1.Protocol,
				Port:            backend1.Port,
				Node:            backend1.Node,
				ServicePortRefs: sets.NewString(svcPortRef1, svcPortRef2),
			}
			Eventually(func() proxycache.SvcPort {
				svcPortCache, exists, _ := proxyController.svcPortCache.GetByKey(proxycache.GenSvcPortKey(svcNs, svcPortName2))
				if !exists || svcPortCache == nil {
					return proxycache.SvcPort{}
				}
				return *(svcPortCache.(*proxycache.SvcPort))
			}, Timeout, Interval).Should(Equal(expSvcPort))

			Eventually(func() bool {
				backCache, exists, _ := proxyController.backendCache.GetByKey(backendKey)
				if !exists || backCache == nil {
					return false
				}
				return equalBackend(backCache.(*proxycache.Backend), &expBackend)
			}, Timeout, Interval).Should(BeTrue())

			Eventually(func(g Gomega) {
				g.Expect(svcIndex.GetSvcOvsInfo(svcID)).Should(BeNil())
				g.Expect(svcIndex.GetDnatFlow(bk1).FlowID).To(Equal(oldDnatMap[bk1]))
			}, Timeout, Interval).Should(Succeed())
		})

		It("servicePort add backend", func() {
			newSvcPort := svcPortCopy
			newSvcPort.Spec.Backends = []everoutesvc.Backend{backend1, backend2}
			Expect(k8sClient.Update(ctx, &newSvcPort)).Should(Succeed())
			expSvcPort := proxycache.SvcPort{
				Name:      svcPortName1,
				Namespace: svcNs,
				PortName:  portName1,
				SvcName:   svcName,
			}
			svcPortRef1 := proxycache.GenServicePortRef(svcNs, svcName, portName1)
			expBackend2 := proxycache.Backend{
				IP:              backend2.IP,
				Protocol:        backend2.Protocol,
				Port:            backend2.Port,
				Node:            backend2.Node,
				ServicePortRefs: sets.NewString(svcPortRef1),
			}
			Eventually(func() proxycache.SvcPort {
				svcPortCache, exists, _ := proxyController.svcPortCache.GetByKey(proxycache.GenSvcPortKey(svcNs, svcPortName1))
				if !exists || svcPortCache == nil {
					return proxycache.SvcPort{}
				}
				return *(svcPortCache.(*proxycache.SvcPort))
			}, Timeout, Interval).Should(Equal(expSvcPort))

			Eventually(func() bool {
				backCache, exists, _ := proxyController.backendCache.GetByKey(bk2)
				if !exists || backCache == nil {
					return false
				}
				return equalBackend(backCache.(*proxycache.Backend), &expBackend2)
			}, Timeout, Interval).Should(BeTrue())

			Eventually(func(g Gomega) {
				g.Expect(svcIndex.GetSvcOvsInfo(svcID)).To(BeNil())
				g.Expect(svcIndex.GetDnatFlow(bk1).FlowID).To(Equal(oldDnatMap[bk1]))
				g.Expect(svcIndex.GetDnatFlow(bk2)).ToNot(BeNil())
			}, Timeout, Interval).Should(Succeed())
		})

		It("servicePort del backend", func() {
			newSvcPort := svcPortCopy
			newSvcPort.Spec.Backends = []everoutesvc.Backend{}
			Expect(k8sClient.Update(ctx, &newSvcPort)).Should(Succeed())
			expSvcPort := proxycache.SvcPort{
				Name:      svcPortName1,
				Namespace: svcNs,
				PortName:  portName1,
				SvcName:   svcName,
			}
			Eventually(func() proxycache.SvcPort {
				svcPortCache, exists, _ := proxyController.svcPortCache.GetByKey(proxycache.GenSvcPortKey(svcNs, svcPortName1))
				if !exists || svcPortCache == nil {
					return proxycache.SvcPort{}
				}
				return *(svcPortCache.(*proxycache.SvcPort))
			}, Timeout, Interval).Should(Equal(expSvcPort))

			Eventually(func() int {
				return len(proxyController.backendCache.List())
			}, Timeout, Interval).Should(BeZero())

			Expect(svcIndex.GetDnatFlow(bk1)).To(BeNil())
		})
	})

	Describe("test servicePort with service", func() {
		var oldOvsInfo *testSvcOvsInfo

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

		BeforeEach(func() {
			svcCopy := svc
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
				InternalTrafficPolicy:  ertype.TrafficPolicyCluster,
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
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyCluster)).ShouldNot(BeNil())
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

		Context("test servicePort", func() {
			svcPort := everoutesvc.ServicePort{
				ObjectMeta: metav1.ObjectMeta{
					Name:      svcPortName1,
					Namespace: svcNs,
					Labels:    map[string]string{everoutesvc.LabelRefEndpoints: svcName},
				},
				Spec: everoutesvc.ServicePortSpec{
					PortName: portName1,
					SvcRef:   svcName,
					Backends: []everoutesvc.Backend{backend1},
				},
			}

			var svcPortCopy everoutesvc.ServicePort
			var oldDnatMap map[string]uint64

			BeforeEach(func() {
				svcPortCopy = svcPort
				Expect(k8sClient.Create(ctx, &svcPortCopy)).Should(Succeed())
				expSvcPort := proxycache.SvcPort{
					Name:      svcPortName1,
					Namespace: svcNs,
					PortName:  portName1,
					SvcName:   svcName,
				}
				svcPortRef := proxycache.GenServicePortRef(svcNs, svcName, portName1)
				expBackend := proxycache.Backend{
					IP:              backend1.IP,
					Protocol:        backend1.Protocol,
					Port:            backend1.Port,
					Node:            backend1.Node,
					ServicePortRefs: sets.NewString(svcPortRef),
				}
				Eventually(func() proxycache.SvcPort {
					svcPortCache, exists, _ := proxyController.svcPortCache.GetByKey(proxycache.GenSvcPortKey(svcNs, svcPortName1))
					if !exists || svcPortCache == nil {
						return proxycache.SvcPort{}
					}
					return *(svcPortCache.(*proxycache.SvcPort))
				}, Timeout, Interval).Should(Equal(expSvcPort))

				Eventually(func() bool {
					backCache, exists, _ := proxyController.backendCache.GetByKey(bk1)
					if !exists || backCache == nil {
						return false
					}
					return equalBackend(backCache.(*proxycache.Backend), &expBackend)
				}, Timeout, Interval).Should(BeTrue())

				Eventually(func(g Gomega) {
					g.Expect(svcIndex.GetDnatFlow(bk1)).ToNot(BeNil())
					ovsInfo := svcIndex.GetSvcOvsInfo(svcID)
					g.Expect(ovsInfo).ToNot(BeNil())
					g.Expect(ovsInfo.GetGroup(portName1, ertype.TrafficPolicyCluster).GroupID).To(Equal(oldOvsInfo.groupMap[portName1][ertype.TrafficPolicyCluster]))
					g.Expect(ovsInfo.GetGroup(portName1, ertype.TrafficPolicyLocal)).ShouldNot(BeNil())
				}, Timeout, Interval).Should(Succeed())
				oldDnatMap = make(map[string]uint64)
				oldDnatMap[bk1] = svcIndex.GetDnatFlow(bk1).FlowID
				ovsInfo := svcIndex.GetSvcOvsInfo(svcID)
				oldOvsInfo.groupMap[portName1][ertype.TrafficPolicyLocal] = ovsInfo.GetGroup(portName1, ertype.TrafficPolicyLocal).GroupID
			})

			AfterEach(func() {
				delSvcPort := everoutesvc.ServicePort{}
				namespaceSelector := client.InNamespace(svcNs)
				labelSelector := client.MatchingLabels{everoutesvc.LabelRefEndpoints: svcName}
				Expect(k8sClient.DeleteAllOf(ctx, &delSvcPort, namespaceSelector, labelSelector)).Should(Succeed())
				Eventually(func() int {
					return len(proxyController.svcPortCache.List())
				}, Timeout, Interval).Should(BeZero())

				Eventually(func() int {
					return len(proxyController.backendCache.List())
				}, Timeout, Interval).Should(BeZero())

				dpOvs := svcIndex.GetSvcOvsInfo(svcID)
				Expect(dpOvs).ToNot(BeNil())
				Expect(dpOvs.GetGroup(portName1, ertype.TrafficPolicyCluster).GroupID).To(Equal(oldOvsInfo.groupMap[portName1][ertype.TrafficPolicyCluster]))
				Expect(dpOvs.GetGroup(portName1, ertype.TrafficPolicyLocal).GroupID).To(Equal(oldOvsInfo.groupMap[portName1][ertype.TrafficPolicyLocal]))
				Expect(svcIndex.GetDnatFlow(bk1)).To(BeNil())
				Expect(svcIndex.GetDnatFlow(bk2)).To(BeNil())
				Expect(svcIndex.GetDnatFlow(bk3)).To(BeNil())
			})

			It("servicePort update backend", func() {
				newSvcPort := svcPortCopy
				newSvcPort.Spec.Backends = []everoutesvc.Backend{backend3}
				Expect(k8sClient.Update(ctx, &newSvcPort)).Should(Succeed())
				expSvcPort := proxycache.SvcPort{
					Name:      svcPortName1,
					Namespace: svcNs,
					PortName:  portName1,
					SvcName:   svcName,
				}
				svcPortRef1 := proxycache.GenServicePortRef(svcNs, svcName, portName1)
				expBackend3 := proxycache.Backend{
					IP:              backend3.IP,
					Protocol:        backend3.Protocol,
					Port:            backend3.Port,
					Node:            backend3.Node,
					ServicePortRefs: sets.NewString(svcPortRef1),
				}
				Eventually(func() proxycache.SvcPort {
					svcPortCache, exists, _ := proxyController.svcPortCache.GetByKey(proxycache.GenSvcPortKey(svcNs, svcPortName1))
					if !exists || svcPortCache == nil {
						return proxycache.SvcPort{}
					}
					return *(svcPortCache.(*proxycache.SvcPort))
				}, Timeout, Interval).Should(Equal(expSvcPort))

				Eventually(func() bool {
					backCache, exists, _ := proxyController.backendCache.GetByKey(bk3)
					if !exists || backCache == nil {
						return false
					}
					return equalBackend(backCache.(*proxycache.Backend), &expBackend3)
				}, Timeout, Interval).Should(BeTrue())

				Eventually(func() bool {
					_, exists, err := proxyController.backendCache.GetByKey(bk1)
					if err != nil {
						return true
					}
					return exists
				}, Timeout, Interval).Should(BeFalse())
				ovsInfo := svcIndex.GetSvcOvsInfo(svcID)
				Expect(ovsInfo).ToNot(BeNil())
				Expect(ovsInfo.GetGroup(portName1, ertype.TrafficPolicyCluster).GroupID).To(Equal(oldOvsInfo.groupMap[portName1][ertype.TrafficPolicyCluster]))
				Expect(ovsInfo.GetGroup(portName1, ertype.TrafficPolicyLocal).GroupID).To(Equal(oldOvsInfo.groupMap[portName1][ertype.TrafficPolicyLocal]))
				Expect(svcIndex.GetDnatFlow(bk1)).To(BeNil())
				Expect(svcIndex.GetDnatFlow(bk3)).ToNot(BeNil())
			})

			It("add servicePort with new portname", func() {
				newSvcPort := everoutesvc.ServicePort{
					ObjectMeta: metav1.ObjectMeta{
						Name:      svcPortName2,
						Namespace: svcNs,
						Labels:    map[string]string{everoutesvc.LabelRefEndpoints: svcName},
					},
					Spec: everoutesvc.ServicePortSpec{
						PortName: portName2,
						SvcRef:   svcName,
						Backends: []everoutesvc.Backend{backend1, backend2},
					},
				}
				Expect(k8sClient.Create(ctx, &newSvcPort)).Should(Succeed())
				expSvcPort := proxycache.SvcPort{
					Name:      svcPortName2,
					Namespace: svcNs,
					PortName:  portName2,
					SvcName:   svcName,
				}
				svcPortRef := proxycache.GenServicePortRef(svcNs, svcName, portName2)
				expBackend := proxycache.Backend{
					IP:              backend2.IP,
					Protocol:        backend2.Protocol,
					Port:            backend2.Port,
					Node:            backend2.Node,
					ServicePortRefs: sets.NewString(svcPortRef),
				}
				Eventually(func() proxycache.SvcPort {
					svcPortCache, exists, _ := proxyController.svcPortCache.GetByKey(proxycache.GenSvcPortKey(svcNs, svcPortName2))
					if !exists || svcPortCache == nil {
						return proxycache.SvcPort{}
					}
					return *(svcPortCache.(*proxycache.SvcPort))
				}, Timeout, Interval).Should(Equal(expSvcPort))

				Eventually(func() bool {
					backCache, exists, _ := proxyController.backendCache.GetByKey(bk2)
					if !exists || backCache == nil {
						return false
					}
					return equalBackend(backCache.(*proxycache.Backend), &expBackend)
				}, Timeout, Interval).Should(BeTrue())

				Expect(svcIndex.GetSvcOvsInfo(svcID)).ToNot(BeNil())
				Expect(svcIndex.GetSvcOvsInfo(svcID).GetGroup(portName2, ertype.TrafficPolicyCluster).GroupID).Should(Equal(oldOvsInfo.groupMap[portName2][ertype.TrafficPolicyCluster]))
				// todo fix ut
				// Expect(svcIndex.GetSvcOvsInfo(svcID).GetGroup(portName2, ertype.TrafficPolicyLocal)).ShouldNot(BeNil())
				Expect(svcIndex.GetDnatFlow(bk1).FlowID).To(Equal(oldDnatMap[bk1]))
				Expect(svcIndex.GetDnatFlow(bk2)).ToNot(BeNil())
			})
		})
	})

	Context("test replay flows", func() {
		baseSvc1 := proxycache.BaseSvc{
			SvcID:      svcID,
			ClusterIPs: []string{ip1},
			Ports: map[string]*proxycache.Port{
				portName1: &port1,
				portName3: &port3,
			},
			SessionAffinity:        corev1.ServiceAffinityClientIP,
			SessionAffinityTimeout: affinityTimeout,
			InternalTrafficPolicy:  ertype.TrafficPolicyLocal,
		}
		baseSvc2 := proxycache.BaseSvc{
			SvcID:      svcID2,
			ClusterIPs: []string{ip2, ip3},
			Ports: map[string]*proxycache.Port{
				portName2: &port2,
			},
			SessionAffinity:       corev1.ServiceAffinityNone,
			InternalTrafficPolicy: ertype.TrafficPolicyCluster,
		}

		svcPort1 := proxycache.SvcPort{
			Name:      svcPortName1,
			Namespace: svcNs,
			SvcName:   svcName,
			PortName:  portName1,
		}
		svcPort2 := proxycache.SvcPort{
			Name:      svcPortName2,
			Namespace: svcNs,
			SvcName:   svcName2,
			PortName:  portName2,
		}
		svcPort3 := proxycache.SvcPort{
			Name:      "svcport-test",
			Namespace: svcNs,
			SvcName:   svcName2,
			PortName:  "test",
		}

		svc1Port1Ref := proxycache.GenServicePortRef(svcNs, svcName, portName1)
		svc1Port3Ref := proxycache.GenServicePortRef(svcNs, svcName, portName3)
		svc2Port2Ref := proxycache.GenServicePortRef(svcNs, svcName2, portName2)
		cacheBk1 := servicePortBackendToCacheBackend(backend1)
		cacheBk1.ServicePortRefs = sets.NewString(svc1Port1Ref, svc2Port2Ref)
		cacheBk2 := servicePortBackendToCacheBackend(backend2)
		cacheBk2.ServicePortRefs = sets.NewString(svc1Port3Ref)

		BeforeEach(func() {
			_ = proxyController.baseSvcCache.Add(&baseSvc1)
			_ = proxyController.baseSvcCache.Add(&baseSvc2)
			_ = proxyController.svcPortCache.Add(&svcPort1)
			_ = proxyController.svcPortCache.Add(&svcPort2)
			_ = proxyController.svcPortCache.Add(&svcPort3)
			_ = proxyController.backendCache.Add(&cacheBk1)
			_ = proxyController.backendCache.Add(&cacheBk2)

			Expect(svcIndex.GetSvcOvsInfo(svcID)).To(BeNil())
			Expect(svcIndex.GetSvcOvsInfo(svcID2)).To(BeNil())
			Expect(svcIndex.GetDnatFlow(bk1)).To(BeNil())
			Expect(svcIndex.GetDnatFlow(bk2)).To(BeNil())
		})

		AfterEach(func() {
			proxyController.syncLock.RLock()
			defer proxyController.syncLock.RUnlock()
			Expect(proxyController.deleteService(ctx, types.NamespacedName{Namespace: svcNs, Name: svcName})).Should(Succeed())
			Expect(proxyController.deleteService(ctx, types.NamespacedName{Namespace: svcNs, Name: svcName2})).Should(Succeed())
			Expect(proxyController.deleteServicePort(ctx, types.NamespacedName{Namespace: svcNs, Name: svcPort1.Name})).Should(Succeed())
			Expect(proxyController.deleteServicePort(ctx, types.NamespacedName{Namespace: svcNs, Name: svcPort2.Name})).Should(Succeed())
			Expect(proxyController.deleteServicePort(ctx, types.NamespacedName{Namespace: svcNs, Name: svcPort3.Name})).Should(Succeed())
			eveSvc1Port3 := everoutesvc.ServicePort{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "unimportant",
					Namespace: svcNs,
				},
				Spec: everoutesvc.ServicePortSpec{
					SvcRef:   svcName,
					PortName: portName3,
				},
			}
			Expect(proxyController.deleteBackendSvcPortRef(&eveSvc1Port3)).Should(Succeed())

			Expect(svcIndex.GetSvcOvsInfo(svcID)).To(BeNil())
			Expect(svcIndex.GetSvcOvsInfo(svcID2)).To(BeNil())
			Expect(svcIndex.GetDnatFlow(bk1)).To(BeNil())
			Expect(svcIndex.GetDnatFlow(bk2)).To(BeNil())
		})

		It("test replay flows", func() {
			syncChan <- ersource.NewReplayEvent()
			Eventually(func(g Gomega) {
				ovsInfo1 := svcIndex.GetSvcOvsInfo(svcID)
				g.Expect(ovsInfo1).ToNot(BeNil())
				g.Expect(ovsInfo1.GetGroup(portName1, ertype.TrafficPolicyCluster)).ShouldNot(BeNil())
				g.Expect(ovsInfo1.GetGroup(portName1, ertype.TrafficPolicyLocal)).ShouldNot(BeNil())
				g.Expect(ovsInfo1.GetGroup(portName3, ertype.TrafficPolicyLocal)).ShouldNot(BeNil())
				g.Expect(ovsInfo1.GetGroup(portName3, ertype.TrafficPolicyCluster)).Should(BeNil())
				g.Expect(ovsInfo1.GetLBFlow(ip1, portName1)).ToNot(BeNil())
				g.Expect(ovsInfo1.GetLBFlow(ip1, portName3)).ToNot(BeNil())
				g.Expect(ovsInfo1.GetSessionAffinityFlow(ip1, portName1)).ToNot(BeNil())
				g.Expect(ovsInfo1.GetSessionAffinityFlow(ip1, portName3)).ToNot(BeNil())

				ovsInfo2 := svcIndex.GetSvcOvsInfo(svcID2)
				g.Expect(ovsInfo2).ToNot(BeNil())
				g.Expect(ovsInfo2.GetGroup(portName2, ertype.TrafficPolicyCluster)).ShouldNot(BeNil())
				g.Expect(ovsInfo2.GetGroup(portName2, ertype.TrafficPolicyLocal)).ShouldNot(BeNil())
				g.Expect(ovsInfo2.GetLBFlow(ip2, portName2)).ToNot(BeNil())
				g.Expect(ovsInfo2.GetLBFlow(ip3, portName2)).ToNot(BeNil())
				g.Expect(ovsInfo2.GetSessionAffinityFlow(ip2, portName2)).To(BeNil())
				g.Expect(ovsInfo2.GetSessionAffinityFlow(ip3, portName3)).To(BeNil())

				g.Expect(svcIndex.GetDnatFlow(bk1)).ToNot(BeNil())
				g.Expect(svcIndex.GetDnatFlow(bk2)).ToNot(BeNil())
			}, Timeout, Interval).Should(Succeed())
		})
	})
})
