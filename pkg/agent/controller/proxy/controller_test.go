package proxy

import (
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
	dpcache "github.com/everoute/everoute/pkg/agent/datapath/cache"
)

var _ = Describe("proxy controller", func() {
	var (
		svcNs    = "default"
		svcName  = "svc1"
		svcName2 = "svc2"
		svcID    = proxycache.GenSvcID(svcNs, svcName)
		svcID2   = proxycache.GenSvcID(svcNs, svcName2)

		ip1             = "10.0.0.12"
		ip2             = "10.3.4.5"
		ip3             = "123.1.1.1"
		lbIP1           = "192.168.1.1"
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
			NodePort: 32001,
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
			Eventually(func() int {
				objs, _ := proxyController.svcLBCache.ByIndex(proxycache.SvcIDIndex, svcID)
				return len(objs)
			}, Timeout, Interval).Should(Equal(0))
			Expect(svcIndex.IsSvcInfoNil(svcID)).Should(BeTrue())
		})

		It("add clusterIP svc", func() {
			svcCopy := svc.DeepCopy()
			svcCopy.Spec.Type = corev1.ServiceTypeClusterIP
			svcCopy.Spec.Ports[0].NodePort = 0
			Expect(k8sClient.Create(ctx, svcCopy)).Should(Succeed())

			expSvcLBs := []*proxycache.SvcLB{
				{
					SvcID: svcID,
					IP:    ip1,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						Port:     port1.Port,
					},
					SessionAffinity: corev1.ServiceAffinityNone,
					TrafficPolicy:   ertype.TrafficPolicyCluster,
				},
			}
			Eventually(func(g Gomega) {
				res, _ := proxyController.svcLBCache.ByIndex(proxycache.SvcIDIndex, svcID)
				g.Expect(len(res)).Should(Equal(len(expSvcLBs)))
				for i := range expSvcLBs {
					res, exists, _ := proxyController.svcLBCache.GetByKey(expSvcLBs[i].ID())
					g.Expect(exists).Should(BeTrue())
					g.Expect(*res.(*proxycache.SvcLB)).Should(Equal(*expSvcLBs[i]))
				}
			}, Timeout, Interval).Should(Succeed())
			dpOvs := svcIndex.GetSvcOvsInfo(svcID)
			Expect(dpOvs).ShouldNot(BeNil())
			Expect(dpOvs.GetLBFlow(ip1, port1.Name)).ShouldNot(Equal(dpcache.UnexistFlowID))
			Expect(dpOvs.GetGroup(port1.Name, ertype.TrafficPolicyCluster)).ShouldNot(Equal(dpcache.UnexistGroupID))
			Expect(dpOvs.GetGroup(port1.Name, ertype.TrafficPolicyLocal)).Should(Equal(dpcache.UnexistGroupID))
		})
		It("add service normal", func() {
			svcCopy := svc.DeepCopy()
			Expect(k8sClient.Create(ctx, svcCopy)).Should(Succeed())

			expSvcLBs := []*proxycache.SvcLB{
				{
					SvcID: svcID,
					IP:    ip1,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						Port:     port1.Port,
					},
					SessionAffinity: corev1.ServiceAffinityNone,
					TrafficPolicy:   ertype.TrafficPolicyCluster,
				},
				{
					SvcID: svcID,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						NodePort: port1.NodePort,
					},
					SessionAffinity: corev1.ServiceAffinityNone,
					TrafficPolicy:   ertype.TrafficPolicyCluster,
				},
			}

			Eventually(func(g Gomega) {
				for i := range expSvcLBs {
					res, exists, _ := proxyController.svcLBCache.GetByKey(expSvcLBs[i].ID())
					g.Expect(exists).Should(BeTrue())
					g.Expect(*res.(*proxycache.SvcLB)).Should(Equal(*expSvcLBs[i]))
				}
			}, Timeout, Interval).Should(Succeed())
			Expect(svcIndex.IsSvcInfoNil(svcID)).Should(BeFalse())
			dpOvs := svcIndex.GetSvcOvsInfo(svcID)
			Expect(dpOvs).ShouldNot(BeNil())
			Expect(dpOvs.GetLBFlow(ip1, port1.Name)).ShouldNot(Equal(dpcache.UnexistFlowID))
			Expect(dpOvs.GetLBFlow("", port1.Name)).ShouldNot(Equal(dpcache.UnexistFlowID))
			Expect(dpOvs.GetGroup(port1.Name, ertype.TrafficPolicyCluster)).ShouldNot(Equal(dpcache.UnexistGroupID))
			Expect(dpOvs.GetGroup(port1.Name, ertype.TrafficPolicyLocal)).Should(Equal(dpcache.UnexistGroupID))
		})

		It("add service with session affinity", func() {
			svcCopy := svc.DeepCopy()
			svcCopy.Spec.SessionAffinity = corev1.ServiceAffinityClientIP
			svcCopy.Spec.SessionAffinityConfig = &corev1.SessionAffinityConfig{
				ClientIP: &corev1.ClientIPConfig{TimeoutSeconds: &affinityTimeout},
			}
			Expect(k8sClient.Create(ctx, svcCopy)).Should(Succeed())
			expSvcLBs := []*proxycache.SvcLB{
				{
					SvcID: svcID,
					IP:    ip1,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						Port:     port1.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID: svcID,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						NodePort: port1.NodePort,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
			}
			Eventually(func(g Gomega) {
				objs, _ := proxyController.svcLBCache.ByIndex(proxycache.SvcIDIndex, svcID)
				g.Expect(len(objs)).Should(Equal(len(expSvcLBs)))
				for i := range expSvcLBs {
					res, exists, _ := proxyController.svcLBCache.GetByKey(expSvcLBs[i].ID())
					g.Expect(exists).Should(BeTrue())
					g.Expect(*res.(*proxycache.SvcLB)).Should(Equal(*expSvcLBs[i]))
				}
			}, Timeout, Interval).Should(Succeed())
			Expect(svcIndex.IsSvcInfoNil(svcID)).Should(BeFalse())
			dpOvs := svcIndex.GetSvcOvsInfo(svcID)
			Expect(dpOvs).ShouldNot(BeNil())
			Expect(dpOvs.GetLBFlow(ip1, port1.Name)).ShouldNot(Equal(dpcache.UnexistFlowID))
			Expect(dpOvs.GetLBFlow("", port1.Name)).ShouldNot(Equal(dpcache.UnexistFlowID))
			Expect(dpOvs.GetGroup(port1.Name, ertype.TrafficPolicyCluster)).ShouldNot(Equal(dpcache.UnexistGroupID))
			Expect(dpOvs.GetGroup(port1.Name, ertype.TrafficPolicyLocal)).Should(Equal(dpcache.UnexistGroupID))
			Expect(dpOvs.GetSessionAffinityFlow(ip1, port1.Name)).ShouldNot(Equal(dpcache.UnexistFlowID))
			Expect(dpOvs.GetSessionAffinityFlow("", port1.Name)).ShouldNot(Equal(dpcache.UnexistFlowID))
		})
		It("add service with internal traffic policy local", func() {
			svcCopy := svc.DeepCopy()
			svcCopy.Spec.SessionAffinity = corev1.ServiceAffinityClientIP
			svcCopy.Spec.SessionAffinityConfig = &corev1.SessionAffinityConfig{
				ClientIP: &corev1.ClientIPConfig{TimeoutSeconds: &affinityTimeout},
			}
			tp := corev1.ServiceInternalTrafficPolicyLocal
			svcCopy.Spec.InternalTrafficPolicy = &tp
			Expect(k8sClient.Create(ctx, svcCopy)).Should(Succeed())
			expSvcLBs := []*proxycache.SvcLB{
				{
					SvcID: svcID,
					IP:    ip1,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						Port:     port1.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyLocal,
				},
				{
					SvcID: svcID,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						NodePort: port1.NodePort,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
			}

			Eventually(func(g Gomega) {
				objs, _ := proxyController.svcLBCache.ByIndex(proxycache.SvcIDIndex, svcID)
				g.Expect(len(objs)).Should(Equal(len(expSvcLBs)))
				for i := range expSvcLBs {
					res, exists, _ := proxyController.svcLBCache.GetByKey(expSvcLBs[i].ID())
					g.Expect(exists).Should(BeTrue())
					g.Expect(*res.(*proxycache.SvcLB)).Should(Equal(*expSvcLBs[i]))
				}
			}, Timeout, Interval).Should(Succeed())
			Expect(svcIndex.IsSvcInfoNil(svcID)).Should(BeFalse())
			dpOvs := svcIndex.GetSvcOvsInfo(svcID)
			Expect(dpOvs).ShouldNot(BeNil())
			Expect(dpOvs.GetLBFlow(ip1, port1.Name)).ShouldNot(Equal(dpcache.UnexistFlowID))
			Expect(dpOvs.GetLBFlow("", port1.Name)).ShouldNot(Equal(dpcache.UnexistFlowID))
			Expect(dpOvs.GetGroup(port1.Name, ertype.TrafficPolicyCluster)).ShouldNot(Equal(dpcache.UnexistGroupID))
			Expect(dpOvs.GetGroup(port1.Name, ertype.TrafficPolicyLocal)).ShouldNot(Equal(dpcache.UnexistGroupID))
			Expect(dpOvs.GetSessionAffinityFlow(ip1, port1.Name)).ShouldNot(Equal(dpcache.UnexistFlowID))
			Expect(dpOvs.GetSessionAffinityFlow("", port1.Name)).ShouldNot(Equal(dpcache.UnexistFlowID))
		})

		It("add lb service with external traffic policy local", func() {
			svcCopy := svc.DeepCopy()
			svcCopy.Spec.Type = corev1.ServiceTypeLoadBalancer
			svcCopy.Spec.SessionAffinity = corev1.ServiceAffinityClientIP
			svcCopy.Spec.SessionAffinityConfig = &corev1.SessionAffinityConfig{
				ClientIP: &corev1.ClientIPConfig{TimeoutSeconds: &affinityTimeout},
			}
			svcCopy.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyLocal
			Expect(k8sClient.Create(ctx, svcCopy)).Should(Succeed())
			Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: svcNs, Name: svcName}, svcCopy)).Should(Succeed())
			svcCopy.Status.LoadBalancer = corev1.LoadBalancerStatus{
				Ingress: []corev1.LoadBalancerIngress{
					{
						IP: lbIP1,
					},
				},
			}
			Expect(k8sClient.Status().Update(ctx, svcCopy)).Should(Succeed())
			expSvcLBs := []*proxycache.SvcLB{
				{
					SvcID: svcID,
					IP:    ip1,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						Port:     port1.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID:  svcID,
					IP:     lbIP1,
					IsLBIP: true,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						Port:     port1.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyLocal,
				},
				{
					SvcID: svcID,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						NodePort: port1.NodePort,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyLocal,
				},
			}

			Eventually(func(g Gomega) {
				objs, _ := proxyController.svcLBCache.ByIndex(proxycache.SvcIDIndex, svcID)
				g.Expect(len(objs)).Should(Equal(len(expSvcLBs)))
				for i := range expSvcLBs {
					res, exists, _ := proxyController.svcLBCache.GetByKey(expSvcLBs[i].ID())
					g.Expect(exists).Should(BeTrue())
					g.Expect(*res.(*proxycache.SvcLB)).Should(Equal(*expSvcLBs[i]))
				}
			}, Timeout, Interval).Should(Succeed())
			dpOvs := svcIndex.GetSvcOvsInfo(svcID)
			Expect(dpOvs).ShouldNot(BeNil())
			Expect(dpOvs.GetLBFlow(ip1, port1.Name)).ShouldNot(Equal(dpcache.UnexistFlowID))
			Expect(dpOvs.GetLBFlow(lbIP1, port1.Name)).ShouldNot(Equal(dpcache.UnexistFlowID))
			Expect(dpOvs.GetLBFlow("", port1.Name)).ShouldNot(Equal(dpcache.UnexistFlowID))
			Expect(dpOvs.GetGroup(port1.Name, ertype.TrafficPolicyCluster)).ShouldNot(Equal(dpcache.UnexistGroupID))
			Expect(dpOvs.GetGroup(port1.Name, ertype.TrafficPolicyLocal)).ShouldNot(Equal(dpcache.UnexistGroupID))
			Expect(dpOvs.GetSessionAffinityFlow(ip1, port1.Name)).ShouldNot(Equal(dpcache.UnexistFlowID))
			Expect(dpOvs.GetSessionAffinityFlow("", port1.Name)).ShouldNot(Equal(dpcache.UnexistFlowID))
			Expect(dpOvs.GetSessionAffinityFlow(lbIP1, port1.Name)).ShouldNot(Equal(dpcache.UnexistFlowID))
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
			objs, _ := proxyController.svcLBCache.ByIndex(proxycache.SvcIDIndex, svcID)
			Expect(len(objs)).Should(Equal(0))
			Expect(svcIndex.IsSvcInfoNil(svcID)).Should(BeTrue())
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
			objs, _ := proxyController.svcLBCache.ByIndex(proxycache.SvcIDIndex, svcID)
			Expect(len(objs)).Should(Equal(0))
			Expect(svcIndex.IsSvcInfoNil(svcID)).Should(BeTrue())
		})
	})

	Context("test update service", func() {
		svc := corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      svcName,
				Namespace: svcNs,
			},
			Spec: corev1.ServiceSpec{
				Type:       corev1.ServiceTypeLoadBalancer,
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
			svcCopy = *svc.DeepCopy()
			Expect(k8sClient.Create(ctx, &svcCopy)).Should(Succeed())
			Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: svcNs, Name: svcName}, &svcCopy))
			svcCopy.Status.LoadBalancer = corev1.LoadBalancerStatus{
				Ingress: []corev1.LoadBalancerIngress{
					{
						IP: lbIP1,
					},
				},
			}
			Expect(k8sClient.Status().Update(ctx, &svcCopy)).Should(Succeed())

			expSvcLBs := []*proxycache.SvcLB{
				{
					SvcID: svcID,
					IP:    ip1,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						Port:     port1.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID:  svcID,
					IP:     lbIP1,
					IsLBIP: true,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						Port:     port1.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID: svcID,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						NodePort: port1.NodePort,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID: svcID,
					IP:    ip1,
					Port: proxycache.Port{
						Name:     port2.Name,
						Protocol: port2.Protocol,
						Port:     port2.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID:  svcID,
					IP:     lbIP1,
					IsLBIP: true,
					Port: proxycache.Port{
						Name:     port2.Name,
						Protocol: port2.Protocol,
						Port:     port2.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
			}

			Eventually(func(g Gomega) {
				objs, _ := proxyController.svcLBCache.ByIndex(proxycache.SvcIDIndex, svcID)
				g.Expect(len(objs)).Should(Equal(len(expSvcLBs) + 1))
				for i := range expSvcLBs {
					res, exists, _ := proxyController.svcLBCache.GetByKey(expSvcLBs[i].ID())
					g.Expect(exists).Should(BeTrue())
					g.Expect(*res.(*proxycache.SvcLB)).Should(Equal(*expSvcLBs[i]))
				}
			}, Timeout, Interval).Should(Succeed())
			Expect(svcIndex.IsSvcInfoNil(svcID)).Should(BeFalse())
			dpOvs := svcIndex.GetSvcOvsInfo(svcID)
			Expect(dpOvs).ShouldNot(BeNil())
			for _, portName := range []string{port1.Name, port2.Name} {
				Expect(dpOvs.GetLBFlow(ip1, portName)).ShouldNot(Equal(dpcache.UnexistFlowID))
				Expect(dpOvs.GetLBFlow(lbIP1, portName)).ShouldNot(Equal(dpcache.UnexistFlowID))
				Expect(dpOvs.GetLBFlow("", portName)).ShouldNot(Equal(dpcache.UnexistFlowID))
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyCluster)).ShouldNot(Equal(dpcache.UnexistGroupID))
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyLocal)).Should(Equal(dpcache.UnexistGroupID))
				Expect(dpOvs.GetSessionAffinityFlow(ip1, portName)).ShouldNot(Equal(dpcache.UnexistFlowID))
				Expect(dpOvs.GetSessionAffinityFlow(lbIP1, portName)).ShouldNot(Equal(dpcache.UnexistFlowID))
				Expect(dpOvs.GetSessionAffinityFlow("", portName)).ShouldNot(Equal(dpcache.UnexistFlowID))
			}
			oldOvsInfo = genTestSvcOvsInfo(dpOvs)
		})

		AfterEach(func() {
			Expect(k8sClient.Delete(ctx, &svc)).Should(Succeed())
			Eventually(func(g Gomega) {
				objs, _ := proxyController.svcLBCache.ByIndex(proxycache.SvcIDIndex, svcID)
				g.Expect(len(objs)).Should(Equal(0))
				g.Expect(svcIndex.IsSvcInfoNil(svcID)).Should(BeTrue())
			}, Timeout, Interval).Should(Succeed())

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
			expSvcLBs := []*proxycache.SvcLB{
				{
					SvcID: svcID,
					IP:    ip1,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						Port:     port1.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID:  svcID,
					IP:     lbIP1,
					IsLBIP: true,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						Port:     port1.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID: svcID,
					IP:    ip1,
					Port: proxycache.Port{
						Name:     port3.Name,
						Protocol: port3.Protocol,
						Port:     port3.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID:  svcID,
					IP:     lbIP1,
					IsLBIP: true,
					Port: proxycache.Port{
						Name:     port3.Name,
						Protocol: port3.Protocol,
						Port:     port3.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID: svcID,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						NodePort: port1.NodePort,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID: svcID,
					Port: proxycache.Port{
						Name:     port3.Name,
						Protocol: port3.Protocol,
						NodePort: port3.NodePort,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID: svcID,
					IP:    ip1,
					Port: proxycache.Port{
						Name:     port2.Name,
						Protocol: port2.Protocol,
						Port:     port2.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID:  svcID,
					IP:     lbIP1,
					IsLBIP: true,
					Port: proxycache.Port{
						Name:     port2.Name,
						Protocol: port2.Protocol,
						Port:     port2.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
			}
			Eventually(func(g Gomega) {
				objs, _ := proxyController.svcLBCache.ByIndex(proxycache.SvcIDIndex, svcID)
				g.Expect(len(objs)).Should(Equal(len(expSvcLBs) + 1))
				for i := range expSvcLBs {
					res, exists, _ := proxyController.svcLBCache.GetByKey(expSvcLBs[i].ID())
					g.Expect(exists).Should(BeTrue())
					g.Expect(*res.(*proxycache.SvcLB)).Should(Equal(*expSvcLBs[i]))
				}
			}, Timeout, Interval).Should(Succeed())
			Expect(svcIndex.IsSvcInfoNil(svcID)).Should(BeFalse())
			dpOvs := svcIndex.GetSvcOvsInfo(svcID)
			Expect(dpOvs).ShouldNot(BeNil())
			for _, portName := range []string{port1.Name, port2.Name} {
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyCluster)).Should(Equal(oldOvsInfo.groupMap[portName][ertype.TrafficPolicyCluster]))
				for _, ip := range []string{ip1, lbIP1, ""} {
					Expect(dpOvs.GetLBFlow(ip, portName)).Should(Equal(oldOvsInfo.lbMap[ip][portName]))
					Expect(dpOvs.GetSessionAffinityFlow(ip, portName)).Should(Equal(oldOvsInfo.sessionAffinityMap[ip][portName]))
				}
			}
			Expect(dpOvs.GetLBFlow(ip1, port3.Name)).ShouldNot(Equal(dpcache.UnexistFlowID))
			Expect(dpOvs.GetLBFlow("", port3.Name)).ShouldNot(Equal(dpcache.UnexistFlowID))
			Expect(dpOvs.GetLBFlow(lbIP1, port3.Name)).ShouldNot(Equal(dpcache.UnexistFlowID))
			Expect(dpOvs.GetGroup(port3.Name, ertype.TrafficPolicyCluster)).ShouldNot(Equal(dpcache.UnexistGroupID))
			Expect(dpOvs.GetGroup(port3.Name, ertype.TrafficPolicyLocal)).Should(Equal(dpcache.UnexistGroupID))
			Expect(dpOvs.GetSessionAffinityFlow(ip1, port3.Name)).ShouldNot(Equal(dpcache.UnexistFlowID))
			Expect(dpOvs.GetSessionAffinityFlow(lbIP1, port3.Name)).ShouldNot(Equal(dpcache.UnexistFlowID))
			Expect(dpOvs.GetSessionAffinityFlow("", port3.Name)).ShouldNot(Equal(dpcache.UnexistFlowID))
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
			expSvcLBs := []*proxycache.SvcLB{
				{
					SvcID: svcID,
					IP:    ip1,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						Port:     port1.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID:  svcID,
					IP:     lbIP1,
					IsLBIP: true,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						Port:     port1.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID: svcID,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						NodePort: port1.NodePort,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
			}
			Eventually(func(g Gomega) {
				objs, _ := proxyController.svcLBCache.ByIndex(proxycache.SvcIDIndex, svcID)
				g.Expect(len(objs)).Should(Equal(len(expSvcLBs)))
				for i := range expSvcLBs {
					res, exists, _ := proxyController.svcLBCache.GetByKey(expSvcLBs[i].ID())
					g.Expect(exists).Should(BeTrue())
					g.Expect(*res.(*proxycache.SvcLB)).Should(Equal(*expSvcLBs[i]))
				}
			}, Timeout, Interval).Should(Succeed())
			Expect(svcIndex.IsSvcInfoNil(svcID)).Should(BeFalse())
			dpOvs := svcIndex.GetSvcOvsInfo(svcID)
			Expect(dpOvs).ShouldNot(BeNil())
			for _, portName := range []string{port1.Name} {
				Expect(dpOvs.GetLBFlow(ip1, portName)).Should(Equal(oldOvsInfo.lbMap[ip1][portName]))
				Expect(dpOvs.GetLBFlow(lbIP1, portName)).Should(Equal(oldOvsInfo.lbMap[lbIP1][portName]))
				Expect(dpOvs.GetLBFlow("", portName)).Should(Equal(oldOvsInfo.lbMap[""][portName]))
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyCluster)).Should(Equal(oldOvsInfo.groupMap[portName][ertype.TrafficPolicyCluster]))
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyLocal)).Should(Equal(dpcache.UnexistGroupID))
				Expect(dpOvs.GetSessionAffinityFlow(ip1, portName)).Should(Equal(oldOvsInfo.sessionAffinityMap[ip1][portName]))
				Expect(dpOvs.GetSessionAffinityFlow(lbIP1, portName)).Should(Equal(oldOvsInfo.sessionAffinityMap[lbIP1][portName]))
				Expect(dpOvs.GetSessionAffinityFlow("", portName)).Should(Equal(oldOvsInfo.sessionAffinityMap[""][portName]))
			}
			Expect(dpOvs.GetLBFlow(ip1, port2.Name)).Should(Equal(dpcache.UnexistFlowID))
			Expect(dpOvs.GetLBFlow(lbIP1, port2.Name)).Should(Equal(dpcache.UnexistFlowID))
			Expect(dpOvs.GetGroup(port2.Name, ertype.TrafficPolicyCluster)).Should(Equal(dpcache.UnexistGroupID))
			Expect(dpOvs.GetGroup(port2.Name, ertype.TrafficPolicyLocal)).Should(Equal(dpcache.UnexistGroupID))
			Expect(dpOvs.GetSessionAffinityFlow(ip1, port2.Name)).Should(Equal(dpcache.UnexistFlowID))
			Expect(dpOvs.GetSessionAffinityFlow(lbIP1, port2.Name)).Should(Equal(dpcache.UnexistFlowID))
		})

		It("change service port without svcPort", func() {
			newService := svcCopy
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
					Port:     1000,
				},
			}
			Expect(k8sClient.Update(ctx, &newService)).Should(Succeed())
			expSvcLBs := []*proxycache.SvcLB{
				{
					SvcID: svcID,
					IP:    ip1,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						Port:     port1.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID:  svcID,
					IP:     lbIP1,
					IsLBIP: true,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						Port:     port1.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID: svcID,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						NodePort: port1.NodePort,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID: svcID,
					IP:    ip1,
					Port: proxycache.Port{
						Name:     port2.Name,
						Protocol: port2.Protocol,
						Port:     1000,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID:  svcID,
					IP:     lbIP1,
					IsLBIP: true,
					Port: proxycache.Port{
						Name:     port2.Name,
						Protocol: port2.Protocol,
						Port:     1000,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
			}
			Eventually(func(g Gomega) {
				objs, _ := proxyController.svcLBCache.ByIndex(proxycache.SvcIDIndex, svcID)
				g.Expect(len(objs)).Should(Equal(len(expSvcLBs) + 1))
				for i := range expSvcLBs {
					res, exists, _ := proxyController.svcLBCache.GetByKey(expSvcLBs[i].ID())
					g.Expect(exists).Should(BeTrue())
					g.Expect(*res.(*proxycache.SvcLB)).Should(Equal(*expSvcLBs[i]))
				}
				g.Expect(svcIndex.IsSvcInfoNil(svcID)).Should(BeFalse())
				dpOvs := svcIndex.GetSvcOvsInfo(svcID)
				g.Expect(dpOvs).ShouldNot(BeNil())
				for _, portName := range []string{port1.Name} {
					g.Expect(dpOvs.GetLBFlow(ip1, portName)).Should(Equal(oldOvsInfo.lbMap[ip1][portName]))
					g.Expect(dpOvs.GetLBFlow(lbIP1, portName)).Should(Equal(oldOvsInfo.lbMap[lbIP1][portName]))
					g.Expect(dpOvs.GetLBFlow("", portName)).Should(Equal(oldOvsInfo.lbMap[""][portName]))
					g.Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyCluster)).Should(Equal(oldOvsInfo.groupMap[portName][ertype.TrafficPolicyCluster]))
					g.Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyLocal)).Should(Equal(dpcache.UnexistGroupID))
					g.Expect(dpOvs.GetSessionAffinityFlow(ip1, portName)).Should(Equal(oldOvsInfo.sessionAffinityMap[ip1][portName]))
					g.Expect(dpOvs.GetSessionAffinityFlow(lbIP1, portName)).Should(Equal(oldOvsInfo.sessionAffinityMap[lbIP1][portName]))
					g.Expect(dpOvs.GetSessionAffinityFlow("", portName)).Should(Equal(oldOvsInfo.sessionAffinityMap[""][portName]))
				}
				// group not change
				g.Expect(dpOvs.GetGroup(port2.Name, ertype.TrafficPolicyCluster)).ShouldNot(Equal(oldOvsInfo.groupMap[port2.Name][ertype.TrafficPolicyCluster]))
				g.Expect(dpOvs.GetGroup(port2.Name, ertype.TrafficPolicyLocal)).Should(Equal(dpcache.UnexistGroupID))

				// flow should change
				g.Expect(dpOvs.GetLBFlow(ip1, port2.Name)).ShouldNot(Equal(oldOvsInfo.lbMap[ip1][port2.Name]))
				g.Expect(dpOvs.GetSessionAffinityFlow(ip1, port2.Name)).ShouldNot(Equal(oldOvsInfo.sessionAffinityMap[ip1][port2.Name]))
			}, Timeout, Interval).Should(Succeed())

		})

		When("change service port with svcPort resource", func() {
			BeforeEach(func() {
				svcPort := everoutesvc.ServicePort{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-portname2",
						Namespace: svcNs,
					},
					Spec: everoutesvc.ServicePortSpec{
						SvcRef:   svcName,
						PortName: port2.Name,
					},
				}
				Expect(k8sClient.Create(ctx, &svcPort)).Should(Succeed())
				Eventually(func(g Gomega) {
					_, exists, _ := proxyController.svcPortCache.GetByKey("default/test-portname2")
					g.Expect(exists).Should(BeTrue())
				}, Timeout, Interval).Should(Succeed())
			})
			AfterEach(func() {
				svcPort := &everoutesvc.ServicePort{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: svcNs, Name: "test-portname2"}, svcPort)).Should(Succeed())
				Expect(k8sClient.Delete(ctx, svcPort)).Should(Succeed())
			})

			It("can't change group", func() {
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

				Eventually(func(g Gomega) {
					g.Expect(svcIndex.IsSvcInfoNil(svcID)).Should(BeFalse())
					dpOvs := svcIndex.GetSvcOvsInfo(svcID)
					g.Expect(dpOvs).ShouldNot(BeNil())
					g.Expect(dpOvs.GetLBFlow(ip1, port2.Name)).ShouldNot(Equal(oldOvsInfo.lbMap[ip1][port2.Name]))
					g.Expect(dpOvs.GetGroup(port2.Name, ertype.TrafficPolicyCluster)).Should(Equal(oldOvsInfo.groupMap[port2.Name][ertype.TrafficPolicyCluster]))
					g.Expect(dpOvs.GetGroup(port2.Name, ertype.TrafficPolicyLocal)).ShouldNot(Equal(dpcache.UnexistGroupID))
					g.Expect(dpOvs.GetSessionAffinityFlow(ip1, port2.Name)).ShouldNot(Equal(oldOvsInfo.sessionAffinityMap[ip1][port2.Name]))
				}, Timeout, Interval).Should(Succeed())
			})
		})

		It("change session affinity mode", func() {
			By("session affinity change from clientip to none")
			newService := svcCopy
			newService.Spec.SessionAffinity = corev1.ServiceAffinityNone
			newService.Spec.SessionAffinityConfig = nil
			Expect(k8sClient.Update(ctx, &newService)).Should(Succeed())
			expSvcLBs := []*proxycache.SvcLB{
				{
					SvcID: svcID,
					IP:    ip1,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						Port:     port1.Port,
					},
					SessionAffinity: corev1.ServiceAffinityNone,
					TrafficPolicy:   ertype.TrafficPolicyCluster,
				},
				{
					SvcID:  svcID,
					IP:     lbIP1,
					IsLBIP: true,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						Port:     port1.Port,
					},
					SessionAffinity: corev1.ServiceAffinityNone,
					TrafficPolicy:   ertype.TrafficPolicyCluster,
				},
				{
					SvcID: svcID,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						NodePort: port1.NodePort,
					},
					SessionAffinity: corev1.ServiceAffinityNone,
					TrafficPolicy:   ertype.TrafficPolicyCluster,
				},
				{
					SvcID: svcID,
					IP:    ip1,
					Port: proxycache.Port{
						Name:     port2.Name,
						Protocol: port2.Protocol,
						Port:     port2.Port,
					},
					SessionAffinity: corev1.ServiceAffinityNone,
					TrafficPolicy:   ertype.TrafficPolicyCluster,
				},
				{
					SvcID:  svcID,
					IP:     lbIP1,
					IsLBIP: true,
					Port: proxycache.Port{
						Name:     port2.Name,
						Protocol: port2.Protocol,
						Port:     port2.Port,
					},
					SessionAffinity: corev1.ServiceAffinityNone,
					TrafficPolicy:   ertype.TrafficPolicyCluster,
				},
			}
			Eventually(func(g Gomega) {
				objs, _ := proxyController.svcLBCache.ByIndex(proxycache.SvcIDIndex, svcID)
				g.Expect(len(objs)).Should(Equal(len(expSvcLBs) + 1))
				for i := range expSvcLBs {
					res, exists, _ := proxyController.svcLBCache.GetByKey(expSvcLBs[i].ID())
					g.Expect(exists).Should(BeTrue())
					g.Expect(*res.(*proxycache.SvcLB)).Should(Equal(*expSvcLBs[i]))
				}
			}, Timeout, Interval).Should(Succeed())
			Expect(svcIndex.IsSvcInfoNil(svcID)).Should(BeFalse())
			dpOvs := svcIndex.GetSvcOvsInfo(svcID)
			Expect(dpOvs).ShouldNot(BeNil())
			for _, portName := range []string{port1.Name, port2.Name} {
				Expect(dpOvs.GetLBFlow(ip1, portName)).Should(Equal(oldOvsInfo.lbMap[ip1][portName]))
				Expect(dpOvs.GetLBFlow(lbIP1, portName)).Should(Equal(oldOvsInfo.lbMap[lbIP1][portName]))
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyCluster)).Should(Equal(oldOvsInfo.groupMap[portName][ertype.TrafficPolicyCluster]))
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyLocal)).Should(Equal(dpcache.UnexistGroupID))
			}
			Expect(dpOvs.GetLBFlow("", port1.Name)).Should(Equal(oldOvsInfo.lbMap[""][port1.Name]))
			Expect(len(dpOvs.GetAllSessionAffinityFlows())).Should(BeZero())

			By("session affinity change from node to clientip, and session affinity config is default")
			newService2 := newService
			newService2.Spec.SessionAffinity = corev1.ServiceAffinityClientIP
			newService2.Spec.SessionAffinityConfig = &corev1.SessionAffinityConfig{ClientIP: nil}
			Expect(k8sClient.Update(ctx, &newService2)).Should(Succeed())
			expSvcLBs = []*proxycache.SvcLB{
				{
					SvcID: svcID,
					IP:    ip1,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						Port:     port1.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: proxycache.DefaultSessionAffinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID:  svcID,
					IP:     lbIP1,
					IsLBIP: true,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						Port:     port1.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: proxycache.DefaultSessionAffinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID: svcID,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						NodePort: port1.NodePort,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: proxycache.DefaultSessionAffinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID: svcID,
					IP:    ip1,
					Port: proxycache.Port{
						Name:     port2.Name,
						Protocol: port2.Protocol,
						Port:     port2.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: proxycache.DefaultSessionAffinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID:  svcID,
					IP:     lbIP1,
					IsLBIP: true,
					Port: proxycache.Port{
						Name:     port2.Name,
						Protocol: port2.Protocol,
						Port:     port2.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: proxycache.DefaultSessionAffinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
			}
			Eventually(func(g Gomega) {
				objs, _ := proxyController.svcLBCache.ByIndex(proxycache.SvcIDIndex, svcID)
				g.Expect(len(objs)).Should(Equal(len(expSvcLBs) + 1))
				for i := range expSvcLBs {
					res, exists, _ := proxyController.svcLBCache.GetByKey(expSvcLBs[i].ID())
					g.Expect(exists).Should(BeTrue())
					g.Expect(*res.(*proxycache.SvcLB)).Should(Equal(*expSvcLBs[i]))
				}
			}, Timeout, Interval).Should(Succeed())
			Expect(svcIndex.IsSvcInfoNil(svcID)).Should(BeFalse())
			dpOvs = svcIndex.GetSvcOvsInfo(svcID)
			for _, portName := range []string{port1.Name, port2.Name} {
				Expect(dpOvs.GetLBFlow(ip1, portName)).Should(Equal(oldOvsInfo.lbMap[ip1][portName]))
				Expect(dpOvs.GetLBFlow(lbIP1, portName)).Should(Equal(oldOvsInfo.lbMap[lbIP1][portName]))
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyCluster)).Should(Equal(oldOvsInfo.groupMap[portName][ertype.TrafficPolicyCluster]))
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyLocal)).Should(Equal(dpcache.UnexistGroupID))
				Expect(dpOvs.GetSessionAffinityFlow(ip1, portName)).ShouldNot(Equal(oldOvsInfo.sessionAffinityMap[ip1][portName]))
			}
			Expect(dpOvs.GetLBFlow("", port1.Name)).Should(Equal(oldOvsInfo.lbMap[""][port1.Name]))
		})

		It("change session affinity timeout", func() {
			newService := svcCopy
			newTimeout := int32(5000)
			newService.Spec.SessionAffinityConfig.ClientIP.TimeoutSeconds = &newTimeout
			Expect(k8sClient.Update(ctx, &newService)).Should(Succeed())
			expSvcLBs := []*proxycache.SvcLB{
				{
					SvcID: svcID,
					IP:    ip1,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						Port:     port1.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: 5000,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID:  svcID,
					IP:     lbIP1,
					IsLBIP: true,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						Port:     port1.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: 5000,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID: svcID,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						NodePort: port1.NodePort,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: 5000,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID: svcID,
					IP:    ip1,
					Port: proxycache.Port{
						Name:     port2.Name,
						Protocol: port2.Protocol,
						Port:     port2.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: 5000,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID:  svcID,
					IP:     lbIP1,
					IsLBIP: true,
					Port: proxycache.Port{
						Name:     port2.Name,
						Protocol: port2.Protocol,
						Port:     port2.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: 5000,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
			}
			Eventually(func(g Gomega) {
				objs, _ := proxyController.svcLBCache.ByIndex(proxycache.SvcIDIndex, svcID)
				g.Expect(len(objs)).Should(Equal(len(expSvcLBs) + 1))
				for i := range expSvcLBs {
					res, exists, _ := proxyController.svcLBCache.GetByKey(expSvcLBs[i].ID())
					g.Expect(exists).Should(BeTrue())
					g.Expect(*res.(*proxycache.SvcLB)).Should(Equal(*expSvcLBs[i]))
				}
			}, Timeout, Interval).Should(Succeed())
			Expect(svcIndex.IsSvcInfoNil(svcID)).Should(BeFalse())
			dpOvs := svcIndex.GetSvcOvsInfo(svcID)
			Expect(dpOvs).ShouldNot(BeNil())
			for _, portName := range []string{port1.Name, port2.Name} {
				for _, ip := range []string{ip1, lbIP1, ""} {
					Expect(dpOvs.GetLBFlow(ip, portName)).Should(Equal(oldOvsInfo.lbMap[ip][portName]))
					Expect(dpOvs.GetSessionAffinityFlow(ip, portName)).ShouldNot(Equal(oldOvsInfo.sessionAffinityMap[ip][portName]))
				}
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyCluster)).Should(Equal(oldOvsInfo.groupMap[portName][ertype.TrafficPolicyCluster]))
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyLocal)).Should(Equal(dpcache.UnexistGroupID))
			}
		})

		It("change InternalTrafficPolicy", func() {
			newService := svcCopy
			tp := corev1.ServiceInternalTrafficPolicyLocal
			newService.Spec.InternalTrafficPolicy = &tp
			Expect(k8sClient.Update(ctx, &newService)).Should(Succeed())
			expSvcLBs := []*proxycache.SvcLB{
				{
					SvcID: svcID,
					IP:    ip1,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						Port:     port1.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyLocal,
				},
				{
					SvcID:  svcID,
					IP:     lbIP1,
					IsLBIP: true,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						Port:     port1.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID: svcID,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						NodePort: port1.NodePort,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID: svcID,
					IP:    ip1,
					Port: proxycache.Port{
						Name:     port2.Name,
						Protocol: port2.Protocol,
						Port:     port2.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyLocal,
				},
				{
					SvcID:  svcID,
					IP:     lbIP1,
					IsLBIP: true,
					Port: proxycache.Port{
						Name:     port2.Name,
						Protocol: port2.Protocol,
						Port:     port2.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
			}
			Eventually(func(g Gomega) {
				objs, _ := proxyController.svcLBCache.ByIndex(proxycache.SvcIDIndex, svcID)
				g.Expect(len(objs)).Should(Equal(len(expSvcLBs) + 1))
				for i := range expSvcLBs {
					res, exists, _ := proxyController.svcLBCache.GetByKey(expSvcLBs[i].ID())
					g.Expect(exists).Should(BeTrue())
					g.Expect(*res.(*proxycache.SvcLB)).Should(Equal(*expSvcLBs[i]))
				}
			}, Timeout, Interval).Should(Succeed())
			Expect(svcIndex.IsSvcInfoNil(svcID)).Should(BeFalse())
			dpOvs := svcIndex.GetSvcOvsInfo(svcID)
			Expect(dpOvs).ShouldNot(BeNil())
			for _, portName := range []string{port1.Name} {
				Expect(dpOvs.GetLBFlow(ip1, portName)).ShouldNot(Equal(oldOvsInfo.lbMap[ip1][portName]))
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyCluster)).Should(Equal(oldOvsInfo.groupMap[portName][ertype.TrafficPolicyCluster]))
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyLocal)).ShouldNot(Equal(dpcache.UnexistGroupID))
				Expect(dpOvs.GetSessionAffinityFlow(ip1, portName)).Should(Equal(oldOvsInfo.sessionAffinityMap[ip1][portName]))
			}

			for _, portName := range []string{port1.Name, port2.Name} {
				for _, ip := range []string{lbIP1, ""} {
					Expect(dpOvs.GetLBFlow(ip, portName)).Should(Equal(oldOvsInfo.lbMap[ip][portName]))
					Expect(dpOvs.GetSessionAffinityFlow(ip, portName)).Should(Equal(oldOvsInfo.sessionAffinityMap[ip][portName]))
				}
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
		var oldOvsInfo *testSvcOvsInfo
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
				dpOvs := svcIndex.GetSvcOvsInfo(svcID)
				g.Expect(dpOvs).ShouldNot(BeNil())
				g.Expect(dpOvs.GetGroup(portName1, ertype.TrafficPolicyCluster)).ShouldNot(Equal(dpcache.UnexistGroupID))
				g.Expect(dpOvs.GetGroup(portName1, ertype.TrafficPolicyLocal)).ShouldNot(Equal(dpcache.UnexistGroupID))
				g.Expect(svcIndex.GetDnatFlow(bk1)).ShouldNot(Equal(dpcache.UnexistFlowID))
			}, Timeout, Interval).Should(Succeed())
			oldDnatMap = make(map[string]uint64)
			oldDnatMap[bk1] = svcIndex.GetDnatFlow(bk1)
			dpOvs := svcIndex.GetSvcOvsInfo(svcID)
			Expect(dpOvs).ShouldNot(BeNil())
			oldOvsInfo = genTestSvcOvsInfo(dpOvs)
		})

		AfterEach(func() {
			delSvcPort := everoutesvc.ServicePort{}
			namespaceSelector := client.InNamespace(svcNs)
			labelSelector := client.MatchingLabels{everoutesvc.LabelRefEndpoints: svcName}
			Expect(k8sClient.DeleteAllOf(ctx, &delSvcPort, namespaceSelector, labelSelector)).Should(Succeed())
			Eventually(func(g Gomega) {
				g.Expect(len(proxyController.svcPortCache.List())).Should(BeZero())
				g.Expect(len(proxyController.backendCache.List())).Should(BeZero())
				g.Expect(svcIndex.IsSvcInfoNil(svcID)).Should(BeTrue())
				g.Expect(svcIndex.GetDnatFlow(bk1)).To(Equal(dpcache.UnexistFlowID))
				g.Expect(svcIndex.GetDnatFlow(bk2)).To(Equal(dpcache.UnexistFlowID))
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
				g.Expect(svcIndex.IsSvcInfoNil(svcID)).Should(BeFalse())
				dpOvs := svcIndex.GetSvcOvsInfo(svcID)
				g.Expect(dpOvs).ShouldNot(BeNil())
				g.Expect(dpOvs.GetGroup(portName2, ertype.TrafficPolicyCluster)).ShouldNot(Equal(dpcache.UnexistGroupID))
				g.Expect(dpOvs.GetGroup(portName2, ertype.TrafficPolicyLocal)).ShouldNot(Equal(dpcache.UnexistGroupID))
				g.Expect(svcIndex.GetDnatFlow(bk1)).To(Equal(oldDnatMap[bk1]))
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
				g.Expect(svcIndex.IsSvcInfoNil(svcID)).Should(BeFalse())
				dpOvs := svcIndex.GetSvcOvsInfo(svcID)
				g.Expect(dpOvs).ShouldNot(BeNil())
				g.Expect(dpOvs.GetGroup(portName1, ertype.TrafficPolicyCluster)).Should(Equal(oldOvsInfo.groupMap[portName1][ertype.TrafficPolicyCluster]))
				g.Expect(dpOvs.GetGroup(portName1, ertype.TrafficPolicyLocal)).Should(Equal(oldOvsInfo.groupMap[portName1][ertype.TrafficPolicyLocal]))
				g.Expect(svcIndex.GetDnatFlow(bk1)).To(Equal(oldDnatMap[bk1]))
				g.Expect(svcIndex.GetDnatFlow(bk2)).ToNot(Equal(dpcache.UnexistFlowID))
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

			Expect(svcIndex.GetDnatFlow(bk1)).To(Equal(dpcache.UnexistFlowID))
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
				Type:       corev1.ServiceTypeLoadBalancer,
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
			expSvcLBs := []*proxycache.SvcLB{
				{
					SvcID: svcID,
					IP:    ip1,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						Port:     port1.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID: svcID,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						NodePort: port1.NodePort,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				{
					SvcID: svcID,
					IP:    ip1,
					Port: proxycache.Port{
						Name:     port2.Name,
						Protocol: port2.Protocol,
						Port:     port2.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
			}
			Eventually(func(g Gomega) {
				objs, _ := proxyController.svcLBCache.ByIndex(proxycache.SvcIDIndex, svcID)
				g.Expect(len(objs)).Should(Equal(len(expSvcLBs) + 1))
				for i := range expSvcLBs {
					res, exists, _ := proxyController.svcLBCache.GetByKey(expSvcLBs[i].ID())
					g.Expect(exists).Should(BeTrue())
					g.Expect(*res.(*proxycache.SvcLB)).Should(Equal(*expSvcLBs[i]))
				}
			}, Timeout, Interval).Should(Succeed())
			dpOvs := svcIndex.GetSvcOvsInfo(svcID)
			Expect(dpOvs).ShouldNot(BeNil())
			for _, portName := range []string{port1.Name, port2.Name} {
				Expect(dpOvs.GetLBFlow(ip1, portName)).ShouldNot(Equal(dpcache.UnexistFlowID))
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyCluster)).ShouldNot(Equal(dpcache.UnexistGroupID))
				Expect(dpOvs.GetSessionAffinityFlow(ip1, portName)).ShouldNot(Equal(dpcache.UnexistFlowID))
			}

			By("add lb ip")
			Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: svcNs, Name: svcName}, &svcCopy)).Should(Succeed())
			svcCopy.Status.LoadBalancer = corev1.LoadBalancerStatus{
				Ingress: []corev1.LoadBalancerIngress{
					{
						IP:       lbIP1,
						Hostname: "hhh",
					},
				},
			}
			Expect(k8sClient.Status().Update(ctx, &svcCopy)).Should(Succeed())
			expSvcLBs = append(expSvcLBs, []*proxycache.SvcLB{
				&proxycache.SvcLB{
					SvcID:  svcID,
					IP:     lbIP1,
					IsLBIP: true,
					Port: proxycache.Port{
						Name:     port1.Name,
						Protocol: port1.Protocol,
						Port:     port1.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
				&proxycache.SvcLB{
					SvcID:  svcID,
					IP:     lbIP1,
					IsLBIP: true,
					Port: proxycache.Port{
						Name:     port2.Name,
						Protocol: port2.Protocol,
						Port:     port2.Port,
					},
					SessionAffinity:        corev1.ServiceAffinityClientIP,
					SessionAffinityTimeout: affinityTimeout,
					TrafficPolicy:          ertype.TrafficPolicyCluster,
				},
			}...)
			Eventually(func(g Gomega) {
				objs, _ := proxyController.svcLBCache.ByIndex(proxycache.SvcIDIndex, svcID)
				g.Expect(len(objs)).Should(Equal(len(expSvcLBs) + 1))
				for i := range expSvcLBs {
					res, exists, _ := proxyController.svcLBCache.GetByKey(expSvcLBs[i].ID())
					g.Expect(exists).Should(BeTrue())
					g.Expect(*res.(*proxycache.SvcLB)).Should(Equal(*expSvcLBs[i]))
				}
			}, Timeout, Interval).Should(Succeed())
			dpOvs = svcIndex.GetSvcOvsInfo(svcID)
			Expect(dpOvs).ShouldNot(BeNil())
			for _, portName := range []string{port1.Name, port2.Name} {
				for _, ip := range []string{ip1, lbIP1, ""} {
					Expect(dpOvs.GetLBFlow(ip, portName)).ShouldNot(Equal(dpcache.UnexistFlowID))
					Expect(dpOvs.GetSessionAffinityFlow(ip, portName)).ShouldNot(Equal(dpcache.UnexistFlowID))
				}
				Expect(dpOvs.GetGroup(portName, ertype.TrafficPolicyCluster)).ShouldNot(Equal(dpcache.UnexistGroupID))
			}
			oldOvsInfo = genTestSvcOvsInfo(dpOvs)
		})

		AfterEach(func() {
			Expect(k8sClient.Delete(ctx, &svc)).Should(Succeed())
			Eventually(func(g Gomega) {
				objs, _ := proxyController.svcLBCache.ByIndex(proxycache.SvcIDIndex, svcID)
				g.Expect(len(objs)).Should(Equal(0))
				g.Expect(svcIndex.IsSvcInfoNil(svcID)).Should(BeTrue())
				g.Expect(len(proxyController.svcPortCache.List())).Should(BeZero())
				g.Expect(len(proxyController.backendCache.List())).Should(BeZero())
			}, Timeout, Interval).Should(Succeed())
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
					g.Expect(svcIndex.GetDnatFlow(bk1)).ToNot(Equal(dpcache.UnexistFlowID))
					ovsInfo := svcIndex.GetSvcOvsInfo(svcID)
					g.Expect(ovsInfo).ToNot(BeNil())
					g.Expect(ovsInfo.GetGroup(portName1, ertype.TrafficPolicyCluster)).To(Equal(oldOvsInfo.groupMap[portName1][ertype.TrafficPolicyCluster]))
					g.Expect(ovsInfo.GetGroup(portName1, ertype.TrafficPolicyLocal)).ShouldNot(Equal(dpcache.UnexistGroupID))
				}, Timeout, Interval).Should(Succeed())
				oldDnatMap = make(map[string]uint64)
				oldDnatMap[bk1] = svcIndex.GetDnatFlow(bk1)
				ovsInfo := svcIndex.GetSvcOvsInfo(svcID)
				oldOvsInfo.groupMap[portName1][ertype.TrafficPolicyLocal] = ovsInfo.GetGroup(portName1, ertype.TrafficPolicyLocal)
			})

			AfterEach(func() {
				delSvcPort := everoutesvc.ServicePort{}
				namespaceSelector := client.InNamespace(svcNs)
				labelSelector := client.MatchingLabels{everoutesvc.LabelRefEndpoints: svcName}
				Expect(k8sClient.DeleteAllOf(ctx, &delSvcPort, namespaceSelector, labelSelector)).Should(Succeed())
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
				Expect(ovsInfo.GetGroup(portName1, ertype.TrafficPolicyCluster)).To(Equal(oldOvsInfo.groupMap[portName1][ertype.TrafficPolicyCluster]))
				Expect(ovsInfo.GetGroup(portName1, ertype.TrafficPolicyLocal)).To(Equal(oldOvsInfo.groupMap[portName1][ertype.TrafficPolicyLocal]))
				Expect(svcIndex.GetDnatFlow(bk1)).To(Equal(dpcache.UnexistFlowID))
				Expect(svcIndex.GetDnatFlow(bk3)).ToNot(Equal(dpcache.UnexistFlowID))
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
				Expect(svcIndex.GetSvcOvsInfo(svcID).GetGroup(portName2, ertype.TrafficPolicyCluster)).Should(Equal(oldOvsInfo.groupMap[portName2][ertype.TrafficPolicyCluster]))
				Expect(svcIndex.GetSvcOvsInfo(svcID).GetGroup(portName2, ertype.TrafficPolicyLocal)).ShouldNot(Equal(dpcache.UnexistGroupID))
				Expect(svcIndex.GetDnatFlow(bk1)).To(Equal(oldDnatMap[bk1]))
				Expect(svcIndex.GetDnatFlow(bk2)).ToNot(Equal(dpcache.UnexistFlowID))
			})
		})
	})

	Context("test replay flows", func() {
		svcLB1 := proxycache.SvcLB{
			SvcID: svcID,
			Port: proxycache.Port{
				Protocol: port1.Protocol,
				NodePort: port1.NodePort,
				Name:     port1.Name,
			},
			TrafficPolicy:          ertype.TrafficPolicyLocal,
			SessionAffinity:        corev1.ServiceAffinityClientIP,
			SessionAffinityTimeout: affinityTimeout,
		}
		svcLB2 := proxycache.SvcLB{
			SvcID: svcID,
			IP:    ip1,
			Port: proxycache.Port{
				Protocol: port3.Protocol,
				Port:     port3.Port,
				Name:     port3.Name,
			},
			TrafficPolicy:          ertype.TrafficPolicyLocal,
			SessionAffinity:        corev1.ServiceAffinityClientIP,
			SessionAffinityTimeout: affinityTimeout,
		}
		svcLB3 := proxycache.SvcLB{
			SvcID:  svcID2,
			IP:     ip2,
			IsLBIP: true,
			Port: proxycache.Port{
				Protocol: port2.Protocol,
				Port:     port2.Port,
				Name:     port2.Name,
			},
			TrafficPolicy:   ertype.TrafficPolicyCluster,
			SessionAffinity: corev1.ServiceAffinityNone,
		}
		svcLB4 := proxycache.SvcLB{
			SvcID: svcID2,
			IP:    ip3,
			Port: proxycache.Port{
				Protocol: port2.Protocol,
				Port:     port2.Port,
				Name:     port2.Name,
			},
			TrafficPolicy:   ertype.TrafficPolicyCluster,
			SessionAffinity: corev1.ServiceAffinityNone,
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
			_ = proxyController.svcLBCache.Add(&svcLB1)
			_ = proxyController.svcLBCache.Add(&svcLB2)
			_ = proxyController.svcLBCache.Add(&svcLB3)
			_ = proxyController.svcLBCache.Add(&svcLB4)
			_ = proxyController.svcPortCache.Add(&svcPort1)
			_ = proxyController.svcPortCache.Add(&svcPort2)
			_ = proxyController.svcPortCache.Add(&svcPort3)
			_ = proxyController.backendCache.Add(&cacheBk1)
			_ = proxyController.backendCache.Add(&cacheBk2)

			Expect(svcIndex.GetSvcOvsInfo(svcID)).To(BeNil())
			Expect(svcIndex.GetSvcOvsInfo(svcID2)).To(BeNil())
			Expect(svcIndex.GetDnatFlow(bk1)).To(Equal(dpcache.UnexistFlowID))
			Expect(svcIndex.GetDnatFlow(bk2)).To(Equal(dpcache.UnexistFlowID))
		})

		AfterEach(func() {
			proxyController.syncLock.RLock()
			defer proxyController.syncLock.RUnlock()
			Expect(proxyController.deleteService(ctx, types.NamespacedName{Namespace: svcNs, Name: svcName})).Should(Succeed())
			Expect(proxyController.deleteService(ctx, types.NamespacedName{Namespace: svcNs, Name: svcName2})).Should(Succeed())
			Expect(proxyController.deleteServicePort(ctx, types.NamespacedName{Namespace: svcNs, Name: svcPort1.Name})).Should(Succeed())
			Expect(proxyController.deleteServicePort(ctx, types.NamespacedName{Namespace: svcNs, Name: svcPort2.Name})).Should(Succeed())
			Expect(proxyController.deleteServicePort(ctx, types.NamespacedName{Namespace: svcNs, Name: svcPort3.Name})).Should(Succeed())
			Expect(proxyController.deleteServicePortForBackend(svcID, portName3)).Should(Succeed())

			Expect(svcIndex.GetSvcOvsInfo(svcID)).To(BeNil())
			Expect(svcIndex.GetSvcOvsInfo(svcID2)).To(BeNil())
			Expect(svcIndex.GetDnatFlow(bk1)).To(Equal(dpcache.UnexistFlowID))
			Expect(svcIndex.GetDnatFlow(bk2)).To(Equal(dpcache.UnexistFlowID))
		})

		It("test replay flows", func() {
			syncChan <- ersource.NewReplayEvent()
			Eventually(func(g Gomega) {
				ovsInfo1 := svcIndex.GetSvcOvsInfo(svcID)
				g.Expect(ovsInfo1).ToNot(BeNil())
				g.Expect(ovsInfo1.GetGroup(portName1, ertype.TrafficPolicyCluster)).ShouldNot(Equal(dpcache.UnexistGroupID))
				g.Expect(ovsInfo1.GetGroup(portName1, ertype.TrafficPolicyLocal)).ShouldNot(Equal(dpcache.UnexistGroupID))
				g.Expect(ovsInfo1.GetGroup(portName3, ertype.TrafficPolicyLocal)).ShouldNot(Equal(dpcache.UnexistGroupID))
				g.Expect(ovsInfo1.GetGroup(portName3, ertype.TrafficPolicyCluster)).Should(Equal(dpcache.UnexistGroupID))
				g.Expect(ovsInfo1.GetLBFlow("", portName1)).ToNot(Equal(dpcache.UnexistFlowID))
				g.Expect(ovsInfo1.GetLBFlow(ip1, portName3)).ToNot(Equal(dpcache.UnexistFlowID))
				g.Expect(ovsInfo1.GetSessionAffinityFlow("", portName1)).ToNot(Equal(dpcache.UnexistFlowID))
				g.Expect(ovsInfo1.GetSessionAffinityFlow(ip1, portName3)).ToNot(Equal(dpcache.UnexistFlowID))

				ovsInfo2 := svcIndex.GetSvcOvsInfo(svcID2)
				g.Expect(ovsInfo2).ToNot(BeNil())
				g.Expect(ovsInfo2.GetGroup(portName2, ertype.TrafficPolicyCluster)).ShouldNot(Equal(dpcache.UnexistGroupID))
				g.Expect(ovsInfo2.GetGroup(portName2, ertype.TrafficPolicyLocal)).ShouldNot(Equal(dpcache.UnexistGroupID))
				g.Expect(ovsInfo2.GetLBFlow(ip2, portName2)).ToNot(Equal(dpcache.UnexistFlowID))
				g.Expect(ovsInfo2.GetLBFlow(ip3, portName2)).ToNot(Equal(dpcache.UnexistFlowID))
				g.Expect(ovsInfo2.GetSessionAffinityFlow(ip2, portName2)).To(Equal(dpcache.UnexistFlowID))
				g.Expect(ovsInfo2.GetSessionAffinityFlow(ip3, portName3)).To(Equal(dpcache.UnexistFlowID))

				g.Expect(svcIndex.GetDnatFlow(bk1)).ToNot(Equal(dpcache.UnexistFlowID))
				g.Expect(svcIndex.GetDnatFlow(bk2)).ToNot(Equal(dpcache.UnexistFlowID))
			}, Timeout, Interval).Should(Succeed())
		})
	})
})
