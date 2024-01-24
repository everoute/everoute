package ipam

import (
	ipamv1alpha1 "github.com/everoute/ipam/api/ipam/v1alpha1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/utils"
)

var _ = Describe("release stale gw ip", func() {
	nodeName := "node10"
	ip1 := "13.13.13.7"
	ip2 := "13.13.13.5"
	pool := ipamv1alpha1.IPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name:      poolName,
			Namespace: ns,
		},
		Spec: ipamv1alpha1.IPPoolSpec{
			Private: true,
			CIDR:    "13.13.13.0/25",
			Gateway: "13.13.13.1",
			Subnet:  "13.13.13.0/24",
		},
	}
	ep := v1alpha1.Endpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      utils.GetGwEndpointName(nodeName),
			Namespace: ns,
		},
	}
	pReq := types.NamespacedName{
		Namespace: ns,
		Name:      poolName,
	}
	node := corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeName,
		},
	}
	BeforeEach(func() {
		p := pool.DeepCopy()
		Expect(k8sClient.Create(ctx, p)).Should(Succeed())
	})
	AfterEach(func() {
		p := ipamv1alpha1.IPPool{}
		Expect(k8sClient.DeleteAllOf(ctx, &p, client.InNamespace(ns))).Should(Succeed())
		ep := v1alpha1.Endpoint{}
		Expect(k8sClient.DeleteAllOf(ctx, &ep, client.InNamespace(ns))).Should(Succeed())
		node := corev1.Node{}
		Expect(k8sClient.DeleteAllOf(ctx, &node)).Should(Succeed())
	})

	Context("ippool hasn't allocate ip", func() {
		When("gateway endpoint and node all doesn't exists", func() {
			It("ippool status doesn't changed", func() {
				c.Process(ctx, k8sClient, k8sClient)
				p := ipamv1alpha1.IPPool{}
				Expect(k8sClient.Get(ctx, pReq, &p)).Should(Succeed())
				Expect(len(p.Status.AllocatedIPs)).Should(Equal(0))
			})
		})
	})

	Context("ippool has allocate cnitype ip", func() {
		BeforeEach(func() {
			p := ipamv1alpha1.IPPool{}
			Expect(k8sClient.Get(ctx, pReq, &p)).Should(Succeed())
			a := make(map[string]ipamv1alpha1.AllocateInfo)
			a[ip1] = ipamv1alpha1.AllocateInfo{
				Type: ipamv1alpha1.AllocateTypeCNIUsed,
				ID:   nodeName,
			}
			a[ip2] = ipamv1alpha1.AllocateInfo{
				Type: ipamv1alpha1.AllocateTypePod,
				ID:   "ns1/pod1",
				CID:  "cid",
			}
			p.Status.AllocatedIPs = a
			Expect(k8sClient.Status().Update(ctx, &p)).Should(Succeed())
		})
		When("gateway endpoint and node all doesn't exists", func() {

			It("release stale gateway ip", func() {
				c.Process(ctx, k8sClient, k8sClient)
				p := ipamv1alpha1.IPPool{}
				Expect(k8sClient.Get(ctx, pReq, &p)).Should(Succeed())
				Expect(p.Status.AllocatedIPs).NotTo(HaveKey(ip1))
				Expect(p.Status.AllocatedIPs).To(HaveKey(ip2))
			})
		})
		When("endpoint exists", func() {
			BeforeEach(func() {
				e := ep.DeepCopy()
				Expect(k8sClient.Create(ctx, e)).Should(Succeed())
			})
			It("doesn't release gateway ip", func() {
				c.Process(ctx, k8sClient, k8sClient)
				p := ipamv1alpha1.IPPool{}
				Expect(k8sClient.Get(ctx, pReq, &p)).Should(Succeed())
				Expect(p.Status.AllocatedIPs).To(HaveKey(ip1))
				Expect(p.Status.AllocatedIPs).To(HaveKey(ip2))
			})
		})
		When("only node exists", func() {
			BeforeEach(func() {
				n := node.DeepCopy()
				Expect(k8sClient.Create(ctx, n)).Should(Succeed())
			})
			It("doesn't release gateway ip", func() {
				c.Process(ctx, k8sClient, k8sClient)
				p := ipamv1alpha1.IPPool{}
				Expect(k8sClient.Get(ctx, pReq, &p)).Should(Succeed())
				Expect(p.Status.AllocatedIPs).To(HaveKey(ip1))
				Expect(p.Status.AllocatedIPs).To(HaveKey(ip2))
			})
		})
	})
})
