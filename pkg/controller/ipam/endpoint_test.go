package ipam

import (
	"context"
	"time"

	ipamv1alpha1 "github.com/everoute/ipam/api/ipam/v1alpha1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
)

var _ = Describe("ipam controller", func() {
	ctx := context.Background()
	nodeName := "node10"
	epName := "gw1"
	ip := "13.13.13.7"
	pool := ipamv1alpha1.IPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name:      poolName,
			Namespace: poolNs,
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
			Name:      epName,
			Namespace: poolNs,
		},
		Spec: v1alpha1.EndpointSpec{
			Reference: v1alpha1.EndpointReference{
				ExternalIDName:  constants.GwEpExternalIDName,
				ExternalIDValue: nodeName,
			},
		},
	}
	epReq := types.NamespacedName{
		Namespace: poolNs,
		Name:      epName,
	}
	pReq := types.NamespacedName{
		Namespace: poolNs,
		Name:      poolName,
	}
	BeforeEach(func() {
		p := pool.DeepCopy()
		Expect(k8sClient.Create(ctx, p)).Should(Succeed())
		a := make(map[string]ipamv1alpha1.AllocateInfo)
		a[ip] = ipamv1alpha1.AllocateInfo{
			Type: ipamv1alpha1.AllocateTypeCNIUsed,
			ID:   nodeName,
		}
		p.Status = ipamv1alpha1.IPPoolStatus{
			AllocatedIPs: a,
		}
		Expect(k8sClient.Status().Update(ctx, p)).Should(Succeed())
	})
	AfterEach(func() {
		p := ipamv1alpha1.IPPool{}
		Expect(k8sClient.DeleteAllOf(ctx, &p, client.InNamespace(poolNs))).Should(Succeed())
		e := v1alpha1.Endpoint{}
		Expect(k8sClient.DeleteAllOf(ctx, &e, client.InNamespace(poolNs))).Should(Succeed())
	})

	Context("delete allocate ip gw endpoint", func() {
		BeforeEach(func() {
			ep1 := ep.DeepCopy()
			Expect(k8sClient.Create(ctx, ep1)).Should(Succeed())
			Eventually(func(g Gomega) {
				ep1 := v1alpha1.Endpoint{}
				g.Expect(k8sClient.Get(ctx, epReq, &ep1)).Should(Succeed())
			}, timeout, interval).Should(Succeed())
		})
		It("success release", func() {
			ep1 := v1alpha1.Endpoint{}
			Expect(k8sClient.Get(ctx, epReq, &ep1)).Should(Succeed())
			Expect(k8sClient.Delete(ctx, &ep1)).Should(Succeed())

			Eventually(func(g Gomega) {
				p := ipamv1alpha1.IPPool{}
				g.Expect(k8sClient.Get(ctx, pReq, &p)).Should(Succeed())
				g.Expect(p.Status.AllocatedIPs).ShouldNot(HaveKey(ip))
			}, timeout, interval).Should(Succeed())
		})
	})

	Context("delete other endpoint", func() {
		BeforeEach(func() {
			ep1 := ep.DeepCopy()
			ep1.Spec.Reference.ExternalIDName = "test"
			Expect(k8sClient.Create(ctx, ep1)).Should(Succeed())
			Eventually(func(g Gomega) {
				ep1 := v1alpha1.Endpoint{}
				g.Expect(k8sClient.Get(ctx, epReq, &ep1)).Should(Succeed())
			}, timeout, interval).Should(Succeed())
		})
		It("doesn't release ip", func() {
			ep1 := v1alpha1.Endpoint{}
			Expect(k8sClient.Get(ctx, epReq, &ep1)).Should(Succeed())
			Expect(k8sClient.Delete(ctx, &ep1)).Should(Succeed())

			time.Sleep(timeout)
			p := ipamv1alpha1.IPPool{}
			Expect(k8sClient.Get(ctx, pReq, &p)).Should(Succeed())
			Expect(p.Status.AllocatedIPs).Should(HaveKey(ip))
		})
	})

	Context("delete unallocate ip gw endpoint", func() {
		BeforeEach(func() {
			ep1 := ep.DeepCopy()
			ep1.Spec.Reference.ExternalIDValue = "test"
			Expect(k8sClient.Create(ctx, ep1)).Should(Succeed())
			Eventually(func(g Gomega) {
				ep1 := v1alpha1.Endpoint{}
				g.Expect(k8sClient.Get(ctx, epReq, &ep1)).Should(Succeed())
			}, timeout, interval).Should(Succeed())
		})
		It("doesn't release ip", func() {
			ep1 := v1alpha1.Endpoint{}
			Expect(k8sClient.Get(ctx, epReq, &ep1)).Should(Succeed())
			Expect(k8sClient.Delete(ctx, &ep1)).Should(Succeed())

			time.Sleep(timeout)
			p := ipamv1alpha1.IPPool{}
			Expect(k8sClient.Get(ctx, pReq, &p)).Should(Succeed())
			Expect(p.Status.AllocatedIPs).Should(HaveKey(ip))
		})
	})
})
