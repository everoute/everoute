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
		Protocol: corev1.ProtocolUDP,
		Port:     22,
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
			if dpOvs != nil {
				Expect(len(dpOvs.GetLBFlowsByIP(ip1))).Should(BeZero())
			}
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
			Expect(dpOvs.GetLBFlow(ip1, port1.Name)).ShouldNot(BeNil())
			Expect(dpOvs.GetGroup(port1.Name)).ShouldNot(BeNil())
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
		})
	})
})
