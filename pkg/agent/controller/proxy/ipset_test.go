package proxy

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/gonetx/ipset"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type testIPSet struct {
	lock   sync.RWMutex
	name   string
	ipset  sets.Set[string]
	addErr error
	delErr error
}

var _ ipset.IPSet = &testIPSet{}

func newTestIPSet(name string) *testIPSet {
	return &testIPSet{
		name:  name,
		ipset: sets.New[string](),
	}
}

func (t *testIPSet) List(options ...ipset.Option) (*ipset.Info, error) {
	return &ipset.Info{
		Name:    t.name,
		Entries: t.ipset.UnsortedList(),
	}, nil
}

func (*testIPSet) ListToFile(filename string, options ...ipset.Option) error { return nil }

func (t *testIPSet) Name() string { return t.name }

func (*testIPSet) Rename(newName string) error { return nil }

func (t *testIPSet) Add(entry string, options ...ipset.Option) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.addErr != nil {
		return t.addErr
	}
	t.ipset.Insert(entry)
	return nil
}

func (t *testIPSet) Del(entry string, options ...ipset.Option) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.delErr != nil {
		return t.delErr
	}
	t.ipset.Delete(entry)
	return nil
}

func (t *testIPSet) Test(entry string) (bool, error) {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return t.ipset.Has(entry), nil
}

func (*testIPSet) Flush() error { return nil }

func (*testIPSet) Destroy() error { return nil }

func (*testIPSet) Save(options ...ipset.Option) (io.Reader, error) { return nil, nil }

func (*testIPSet) SaveToFile(filename string, options ...ipset.Option) error { return nil }

func (*testIPSet) Restore(r io.Reader, exist ...bool) error { return nil }

func (*testIPSet) RestoreFromFile(filename string, exist ...bool) error { return nil }

func (t *testIPSet) resetErr() {
	t.addErr = nil
	t.delErr = nil
}

func ipSetIsEmpty(in ipset.IPSet) bool {
	info, _ := in.List()
	return len(info.Entries) == 0
}
func ipsetTest(in ipset.IPSet, entry string) bool {
	res, _ := in.Test(entry)
	return res
}

var _ = Describe("ipset controller", func() {
	AfterEach(func() {
		ipsetCtrl.TCPSet.(*testIPSet).resetErr()
		ipsetCtrl.UDPSet.(*testIPSet).resetErr()
		ipsetCtrl.LBSet.(*testIPSet).resetErr()
		svcList := corev1.ServiceList{}
		Expect(k8sClient.List(ctx, &svcList, client.InNamespace(ipsetNs))).ToNot(HaveOccurred())
		for i := range svcList.Items {
			Expect(k8sClient.Delete(ctx, &svcList.Items[i])).ToNot(HaveOccurred())
		}
		Eventually(func(g Gomega) {
			g.Expect(ipSetIsEmpty(ipsetCtrl.TCPSet)).Should(BeTrue())
			g.Expect(ipSetIsEmpty(ipsetCtrl.UDPSet)).Should(BeTrue())
			g.Expect(ipSetIsEmpty(ipsetCtrl.LBSet)).Should(BeTrue())
			g.Expect(len(ipsetCtrl.lbIPPorts)).Should(Equal(0))
			g.Expect(len(ipsetCtrl.nodePorts)).Should(Equal(0))
		}, Timeout, Interval).Should(Succeed())
	})

	Context("svc type=LoadBalancer", func() {
		svcType := corev1.ServiceTypeLoadBalancer
		It("create svc without lb ip", func() {
			svc := assembleSvc(svcType, 0, 1)
			By("crate svc")
			Expect(k8sClient.Create(ctx, svc.DeepCopy())).ToNot(HaveOccurred())

			By("check ipset and cache")
			if svc.Spec.AllocateLoadBalancerNodePorts == nil || !*svc.Spec.AllocateLoadBalancerNodePorts {
				time.Sleep(5)
			}
			Eventually(check, Timeout, Interval).WithArguments(svc).Should(Succeed())
		})
		It("create svc with lb ip", func() {
			svc := assembleSvc(svcType, 3, 2)
			By("crate svc")
			Expect(k8sClient.Create(ctx, svc.DeepCopy())).ToNot(HaveOccurred())
			Expect(k8sClient.Status().Update(ctx, svc.DeepCopy())).ToNot(HaveOccurred())

			By("check ipset and cache")
			Eventually(check, Timeout, Interval).WithArguments(svc).Should(Succeed())
		})
		It("add svc lb ip", func() {
			svc := assembleSvc(svcType, 2, 2)
			By("crate svc")
			Expect(k8sClient.Create(ctx, svc.DeepCopy())).ToNot(HaveOccurred())
			Expect(k8sClient.Status().Update(ctx, svc.DeepCopy())).ToNot(HaveOccurred())

			By("add lb ip")
			svc.Status.LoadBalancer.Ingress = append(svc.Status.LoadBalancer.Ingress, corev1.LoadBalancerIngress{IP: genIP()})
			Expect(k8sClient.Status().Update(ctx, svc.DeepCopy())).ToNot(HaveOccurred())

			By("check ipset and cache")
			Eventually(check, Timeout, Interval).WithArguments(svc).Should(Succeed())
		})
		It("del svc lb ip", func() {
			svc := assembleSvc(svcType, 2, 2)
			By("crate svc")
			Expect(k8sClient.Create(ctx, svc.DeepCopy())).ToNot(HaveOccurred())
			Expect(k8sClient.Status().Update(ctx, svc.DeepCopy())).ToNot(HaveOccurred())

			By("del lb ip")
			svc.Status.LoadBalancer.Ingress = nil
			Expect(k8sClient.Status().Update(ctx, svc.DeepCopy())).ToNot(HaveOccurred())

			By("check ipset and cache")
			Eventually(check, Timeout, Interval).WithArguments(svc).Should(Succeed())
		})
		It("update svc lb ip when ipset add failed", func() {
			svc := assembleSvc(svcType, 2, 2)
			By("crate svc")
			Expect(k8sClient.Create(ctx, svc.DeepCopy())).ToNot(HaveOccurred())
			Expect(k8sClient.Status().Update(ctx, svc.DeepCopy())).ToNot(HaveOccurred())
			Eventually(check, Timeout, Interval).WithArguments(svc).Should(Succeed())

			By("set ipset add err")
			ipsetCtrl.LBSet.(*testIPSet).addErr = errors.New("add failed")

			By("update lb ip")
			svc.Status.LoadBalancer.Ingress[1].IP = genIP()
			Expect(k8sClient.Status().Update(ctx, svc.DeepCopy())).ToNot(HaveOccurred())

			By("check ipset and cache, should del old success, but add new failed")
			svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{svc.Status.LoadBalancer.Ingress[0]}
			Eventually(check, Timeout, Interval).WithArguments(svc).Should(Succeed())
		})
		It("update svc lb ip when ipset del failed", func() {
			svc := assembleSvc(svcType, 2, 2)
			By("crate svc")
			Expect(k8sClient.Create(ctx, svc.DeepCopy())).ToNot(HaveOccurred())
			Expect(k8sClient.Status().Update(ctx, svc.DeepCopy())).ToNot(HaveOccurred())
			Eventually(check, Timeout, Interval).WithArguments(svc).Should(Succeed())

			By("set ipset add err")
			ipsetCtrl.LBSet.(*testIPSet).delErr = errors.New("del failed")

			By("update lb ip")
			newIP := genIP()
			svcCopy := svc.DeepCopy()
			svcCopy.Status.LoadBalancer.Ingress[1].IP = newIP
			Expect(k8sClient.Status().Update(ctx, svcCopy)).ToNot(HaveOccurred())

			By("check ipset and cache, should add new success but del old failed")
			svc.Status.LoadBalancer.Ingress = append(svc.Status.LoadBalancer.Ingress, corev1.LoadBalancerIngress{IP: newIP})
			Eventually(check, Timeout, Interval).WithArguments(svc).Should(Succeed())
		})
		It("add svc port", func() {
			svc := assembleSvc(svcType, 1, 1)
			By("crate svc")
			Expect(k8sClient.Create(ctx, svc.DeepCopy())).ToNot(HaveOccurred())
			Expect(k8sClient.Status().Update(ctx, svc.DeepCopy())).ToNot(HaveOccurred())

			By("add port")
			svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{Protocol: genPortProto(), Port: genPortNumber(), NodePort: genNodePortNumber(), Name: genPortName()})
			svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{Protocol: genPortProto(), Port: genPortNumber(), NodePort: genNodePortNumber(), Name: genPortName()})
			Expect(k8sClient.Update(ctx, svc.DeepCopy())).ToNot(HaveOccurred())

			By("check ipset and cache")
			Eventually(check, Timeout, Interval).WithArguments(svc).Should(Succeed())
		})
		It("del svc port", func() {
			svc := assembleSvc(svcType, 2, 3)
			By("crate svc")
			Expect(k8sClient.Create(ctx, svc.DeepCopy())).ToNot(HaveOccurred())
			Expect(k8sClient.Status().Update(ctx, svc.DeepCopy())).ToNot(HaveOccurred())
			Eventually(check, Timeout, Interval).WithArguments(svc).Should(Succeed())

			By("del port")
			svc.Spec.Ports = []corev1.ServicePort{svc.Spec.Ports[1]}
			Expect(k8sClient.Update(ctx, svc.DeepCopy())).ToNot(HaveOccurred())

			By("check ipset and cache")
			Eventually(check, Timeout, Interval).WithArguments(svc).Should(Succeed())
		})
		It("modify port number", func() {
			svc := assembleSvc(svcType, 1, 2)
			By("crate svc")
			Expect(k8sClient.Create(ctx, svc.DeepCopy())).ToNot(HaveOccurred())
			Expect(k8sClient.Status().Update(ctx, svc.DeepCopy())).ToNot(HaveOccurred())

			By("change port number")
			svc.Spec.Ports[1].Port = genPortNumber()
			Expect(k8sClient.Update(ctx, svc.DeepCopy())).ToNot(HaveOccurred())

			By("check ipset and cache")
			Expect(len(svc.Spec.Ports)).Should(Equal(2))
			Eventually(check, Timeout, Interval).WithArguments(svc).Should(Succeed())
		})
		It("modify port name", func() {
			svc := assembleSvc(svcType, 1, 2)
			By("crate svc")
			Expect(k8sClient.Create(ctx, svc.DeepCopy())).ToNot(HaveOccurred())
			Expect(k8sClient.Status().Update(ctx, svc.DeepCopy())).ToNot(HaveOccurred())
			Eventually(check, Timeout, Interval).WithArguments(svc).Should(Succeed())

			By("change port name")
			svc.Spec.Ports[1].Name = genPortName()
			Expect(k8sClient.Update(ctx, svc.DeepCopy())).ToNot(HaveOccurred())

			By("check ipset and cache")
			time.Sleep(5)
			Eventually(check, Timeout, Interval).WithArguments(svc).Should(Succeed())
		})
		It("del svc normal", func() {
			svc1 := assembleSvc(svcType, 1, 2)
			By("crate svc")
			Expect(k8sClient.Create(ctx, svc1.DeepCopy())).ToNot(HaveOccurred())
			Expect(k8sClient.Status().Update(ctx, svc1.DeepCopy())).ToNot(HaveOccurred())
			Eventually(check, Timeout, Interval).WithArguments(svc1).Should(Succeed())

			By("delete svc")
			Expect(k8sClient.Delete(ctx, svc1.DeepCopy())).ToNot(HaveOccurred())

			By("check ipset and cache")
			Eventually(checkDel, Timeout, Interval).WithArguments(svc1).Should(Succeed())
		})
		It("del svc has same lb ip and port with exist svc", func() {
			svc1 := assembleSvc(svcType, 1, 2)
			svc2 := assembleSvc(svcType, 1, 2)
			svc2Copy := svc2.DeepCopy()
			svc2Copy.Status.LoadBalancer.Ingress = append(svc2.Status.LoadBalancer.Ingress, svc1.Status.LoadBalancer.Ingress[0])
			svc2Copy.Spec.Ports[1] = svc1.Spec.Ports[0]
			svc2Copy.Spec.Ports[1].NodePort = genNodePortNumber()
			By("crate svc")
			Expect(k8sClient.Create(ctx, svc1.DeepCopy())).ToNot(HaveOccurred())
			Expect(k8sClient.Status().Update(ctx, svc1.DeepCopy())).ToNot(HaveOccurred())
			Expect(k8sClient.Create(ctx, svc2Copy.DeepCopy())).ToNot(HaveOccurred())
			Expect(k8sClient.Status().Update(ctx, svc2Copy.DeepCopy())).ToNot(HaveOccurred())
			Eventually(check, Timeout, Interval).WithArguments(svc2Copy).Should(Succeed())
			Eventually(check, Timeout, Interval).WithArguments(svc1).Should(Succeed())

			By("delete svc")
			Expect(k8sClient.Delete(ctx, svc2Copy.DeepCopy())).ToNot(HaveOccurred())

			By("check ipset and cache")
			// must check del first
			Eventually(checkDel, Timeout, Interval).WithArguments(svc2).Should(Succeed())
			Eventually(check, Timeout, Interval).WithArguments(svc1).Should(Succeed())
		})
	})
	Context("svc type=NodePort", func() {
		svcType := corev1.ServiceTypeNodePort
		It("create svc", func() {
			svc := assembleSvc(svcType, 0, 2)
			By("crate svc")
			Expect(k8sClient.Create(ctx, svc.DeepCopy())).ToNot(HaveOccurred())

			By("check ipset and cache")
			Eventually(check, Timeout, Interval).WithArguments(svc).Should(Succeed())
		})
		It("add port", func() {
			svc := assembleSvc(svcType, 0, 2)
			By("crate svc")
			Expect(k8sClient.Create(ctx, svc.DeepCopy())).ToNot(HaveOccurred())

			By("add port")
			svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{Protocol: genPortProto(), Port: genPortNumber(), NodePort: genNodePortNumber(), Name: genPortName()})
			Expect(k8sClient.Update(ctx, svc.DeepCopy())).ToNot(HaveOccurred())

			By("check ipset and cache")
			Eventually(check, Timeout, Interval).WithArguments(svc).Should(Succeed())
		})
		It("del port", func() {
			svc := assembleSvc(svcType, 0, 5)
			By("crate svc")
			Expect(k8sClient.Create(ctx, svc.DeepCopy())).ToNot(HaveOccurred())

			By("add port")
			svc.Spec.Ports = []corev1.ServicePort{svc.Spec.Ports[0], svc.Spec.Ports[4]}
			Expect(k8sClient.Update(ctx, svc.DeepCopy())).ToNot(HaveOccurred())

			By("check ipset and cache")
			Eventually(check, Timeout, Interval).WithArguments(svc).Should(Succeed())
		})
		It("update node port number", func() {
			svc := assembleSvc(svcType, 0, 5)
			By("crate svc")
			Expect(k8sClient.Create(ctx, svc.DeepCopy())).ToNot(HaveOccurred())

			By("update port")
			svc.Spec.Ports[0].NodePort = genNodePortNumber()
			svc.Spec.Ports[3].NodePort = genNodePortNumber()
			Expect(k8sClient.Update(ctx, svc.DeepCopy())).ToNot(HaveOccurred())

			By("check ipset and cache")
			Eventually(check, Timeout, Interval).WithArguments(svc).Should(Succeed())
		})
		It("update node port number when ipset add err", func() {
			svc := assembleSvc(svcType, 0, 2)
			svc.Spec.Ports[0].Protocol = corev1.ProtocolTCP
			By("crate svc")
			Expect(k8sClient.Create(ctx, svc.DeepCopy())).ToNot(HaveOccurred())
			Eventually(check, Timeout, Interval).WithArguments(svc).Should(Succeed())

			By("set ipsetTCP add err")
			ipsetCtrl.TCPSet.(*testIPSet).addErr = errors.New("test add err")

			By("update node port number")
			svc.Spec.Ports[0].NodePort = genNodePortNumber()
			Expect(k8sClient.Update(ctx, svc.DeepCopy())).ToNot(HaveOccurred())

			By("check ipset and cache, should del old success, but add new failed")
			svc.Spec.Ports = []corev1.ServicePort{svc.Spec.Ports[1]}
			Eventually(check, Timeout, Interval).WithArguments(svc).Should(Succeed())
		})
		It("update node port number when ipset del err", func() {
			svc := assembleSvc(svcType, 0, 2)
			svc.Spec.Ports[0].Protocol = corev1.ProtocolUDP
			By("crate svc")
			Expect(k8sClient.Create(ctx, svc.DeepCopy())).ToNot(HaveOccurred())
			Eventually(check, Timeout, Interval).WithArguments(svc).Should(Succeed())

			By("set ipsetTCP add err")
			ipsetCtrl.UDPSet.(*testIPSet).delErr = errors.New("test add err")

			By("update node port number")
			newPort := genNodePortNumber()
			svcCopy := svc.DeepCopy()
			svcCopy.Spec.Ports[0].NodePort = newPort
			Expect(k8sClient.Update(ctx, svcCopy)).ToNot(HaveOccurred())

			By("check ipset and cache, should del old failed, but add new success")
			svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{Protocol: corev1.ProtocolUDP, Name: genPortName(), NodePort: newPort, Port: genPortNumber()})
			Eventually(check, Timeout, Interval).WithArguments(svc).Should(Succeed())
		})
		It("del svc normal", func() {
			svc := assembleSvc(svcType, 0, 2)
			By("crate svc")
			Expect(k8sClient.Create(ctx, svc.DeepCopy())).ToNot(HaveOccurred())
			Expect(k8sClient.Status().Update(ctx, svc.DeepCopy())).ToNot(HaveOccurred())
			Eventually(check, Timeout, Interval).WithArguments(svc).Should(Succeed())

			By("delete svc")
			Expect(k8sClient.Delete(ctx, svc.DeepCopy())).ToNot(HaveOccurred())

			By("check ipset and cache")
			Eventually(checkDel, Timeout, Interval).WithArguments(svc).Should(Succeed())
		})
	})
})

func assembleSvc(svcType corev1.ServiceType, lbIPNum, portNum int) *corev1.Service {
	svc := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      genSvcName(),
			Namespace: ipsetNs,
		},
		Spec: corev1.ServiceSpec{
			Type: svcType,
		},
	}

	for i := 0; i < lbIPNum; i++ {
		svc.Status.LoadBalancer.Ingress = append(svc.Status.LoadBalancer.Ingress, corev1.LoadBalancerIngress{IP: genIP()})
	}

	for i := 0; i < portNum; i++ {
		svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{Name: genPortName(), Protocol: genPortProto(), Port: genPortNumber(), NodePort: genNodePortNumber()})
	}

	return &svc
}

func check(g Gomega, svc *corev1.Service) {
	svcID := svc.GetNamespace() + "/" + svc.GetName()

	ipsetCtrl.lbLock.RLock()
	ipsetCtrl.npLock.RLock()
	defer ipsetCtrl.npLock.RUnlock()
	defer ipsetCtrl.lbLock.RUnlock()

	// check nodeports
	tcpPorts := sets.New[int32]()
	udpPorts := sets.New[int32]()
	for _, p := range svc.Spec.Ports {
		if p.Protocol == corev1.ProtocolTCP {
			tcpPorts.Insert(p.NodePort)
			g.Expect(ipsetTest(ipsetCtrl.TCPSet, fmt.Sprintf("%d", p.NodePort))).Should(BeTrue())
		}
		if p.Protocol == corev1.ProtocolUDP {
			udpPorts.Insert(p.NodePort)
			g.Expect(ipsetTest(ipsetCtrl.UDPSet, fmt.Sprintf("%d", p.NodePort))).Should(BeTrue())
		}
	}
	if tcpPorts.Len() == 0 {
		if ipsetCtrl.lbIPPorts[svc.GetName()] != nil {
			g.Expect(ipsetCtrl.nodePorts[svcID][TCP]).Should(BeNil())
		}
	} else {
		g.Expect(ipsetCtrl.nodePorts[svcID][TCP]).Should(Equal(tcpPorts))
	}
	if udpPorts.Len() == 0 {
		if ipsetCtrl.lbIPPorts[svc.GetName()] != nil {
			g.Expect(ipsetCtrl.nodePorts[svcID][UDP]).Should(BeNil())
		}
	} else {
		g.Expect(ipsetCtrl.nodePorts[svcID][UDP]).Should(Equal(udpPorts))
	}

	// check LB
	if isLbSvc(svc) {
		lbIPPorts := sets.New[IPPort]()
		for i := range svc.Status.LoadBalancer.Ingress {
			ip := svc.Status.LoadBalancer.Ingress[i].IP
			if strings.Contains(ip, ":") {
				continue
			}
			for _, p := range svc.Spec.Ports {
				if p.Protocol == corev1.ProtocolSCTP {
					continue
				}
				ipPort := NewIPPort(ip, p.Protocol, p.Port)
				g.Expect(ipsetTest(ipsetCtrl.LBSet, ipPort.String())).Should(BeTrue())
				lbIPPorts.Insert(*ipPort)
			}
		}
		if lbIPPorts.Len() == 0 {
			g.Expect(ipsetCtrl.lbIPPorts[svcID]).Should(BeNil())
		} else {
			g.Expect(ipsetCtrl.lbIPPorts[svcID]).Should(Equal(lbIPPorts))
		}
	}
}

func checkDel(g Gomega, svc *corev1.Service) {
	svcID := svc.GetNamespace() + "/" + svc.GetName()

	ipsetCtrl.lbLock.RLock()
	ipsetCtrl.npLock.RLock()
	defer ipsetCtrl.npLock.RUnlock()
	defer ipsetCtrl.lbLock.RUnlock()

	// check nodeports
	tcpPorts := sets.New[int32]()
	udpPorts := sets.New[int32]()
	for _, p := range svc.Spec.Ports {
		if p.Protocol == corev1.ProtocolTCP {
			tcpPorts.Insert(p.NodePort)
			g.Expect(ipsetTest(ipsetCtrl.TCPSet, fmt.Sprintf("%d", p.NodePort))).Should(BeFalse())
		}
		if p.Protocol == corev1.ProtocolUDP {
			udpPorts.Insert(p.NodePort)
			g.Expect(ipsetTest(ipsetCtrl.UDPSet, fmt.Sprintf("%d", p.NodePort))).Should(BeFalse())
		}
	}
	g.Expect(ipsetCtrl.nodePorts[svcID]).Should(BeNil())

	// check LB
	if isLbSvc(svc) {
		lbIPPorts := sets.New[IPPort]()
		for i := range svc.Status.LoadBalancer.Ingress {
			ip := svc.Status.LoadBalancer.Ingress[i].IP
			for _, p := range svc.Spec.Ports {
				if p.Protocol == corev1.ProtocolSCTP {
					continue
				}
				ipPort := NewIPPort(ip, p.Protocol, p.Port)
				g.Expect(ipsetTest(ipsetCtrl.LBSet, ipPort.String())).Should(BeFalse())
				lbIPPorts.Insert(*ipPort)
			}
		}
		g.Expect(ipsetCtrl.lbIPPorts[svcID]).Should(BeNil())
	}
}
