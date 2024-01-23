package ippool

import (
	ipamv1alpha1 "github.com/everoute/ipam/api/ipam/v1alpha1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

var _ = Describe("ippool controller", func() {
	pool1 := types.NamespacedName{
		Namespace: Ns,
		Name:      "pool1",
	}
	pool2 := types.NamespacedName{
		Namespace: Ns,
		Name:      "pool2",
	}
	ippool1 := ipamv1alpha1.IPPool{
		ObjectMeta: v1.ObjectMeta{
			Name:      pool1.Name,
			Namespace: Ns,
		},
	}
	ippool2 := ipamv1alpha1.IPPool{
		ObjectMeta: v1.ObjectMeta{
			Name:      pool2.Name,
			Namespace: Ns,
		},
	}

	AfterEach(func() {
		resetErr()
		Expect(r.deleteIPPool(pool1)).ToNot(HaveOccurred())
		Expect(r.deleteIPPool(pool2)).ToNot(HaveOccurred())
		Expect(len(r.gws)).Should(Equal(0))
		Expect(len(r.subnets)).Should(Equal(0))
		Expect(iptCtrl.cidrs.Len()).Should(Equal(0))
		Expect(routeCtrl.cidrs.Len()).Should(Equal(0))

		gws, err := dumpLocalBrIcmpReply()
		Expect(err).ToNot(HaveOccurred())
		Expect(len(gws)).Should(Equal(0))
		subnets, err := dumpLocalBrArpProxy()
		Expect(err).ToNot(HaveOccurred())
		Expect(len(subnets)).Should(Equal(0))
		subnets, err = dumpUplinkBrIPForward()
		Expect(err).ToNot(HaveOccurred())
		Expect(subnets).Should(HaveExactElements(gwIPPoolSubnet))
	})

	Context("add ippool", func() {
		BeforeEach(func() {
			resetErr()
			ippool1.Spec = ipamv1alpha1.IPPoolSpec{
				Gateway: pool1Gw,
				CIDR:    pool1Cidr,
				Subnet:  pool1Subnet,
			}
		})

		It("normal", func() {
			Expect(r.addIPPool(&ippool1)).ToNot(HaveOccurred())
			Expect(r.subnets).Should(HaveKey(pool1Subnet))
			Expect(r.subnets[pool1Subnet].UnsortedList()).Should(ContainElements(pool1))
			Expect(r.gws).Should(HaveKey(pool1Gw))
			Expect(r.gws[pool1Gw].UnsortedList()).Should(ContainElements(pool1))

			Expect(iptCtrl.cidrs.Has(pool1Subnet)).Should(BeTrue())
			Expect(routeCtrl.cidrs.Has(pool1Subnet)).Should(BeTrue())

			gws, err := dumpLocalBrIcmpReply()
			Expect(err).ToNot(HaveOccurred())
			Expect(gws).Should(ContainElements(pool1Gw))

			subnets, err := dumpLocalBrArpProxy()
			Expect(err).ToNot(HaveOccurred())
			Expect(subnets).Should(ContainElements(pool1Subnet))
			subnets, err = dumpUplinkBrIPForward()
			Expect(err).ToNot(HaveOccurred())
			Expect(subnets).Should(ContainElements(pool1Subnet))
		})

		When("invalid subnet", func() {
			BeforeEach(func() {
				ippool1.Spec = ipamv1alpha1.IPPoolSpec{
					Gateway: pool1Gw,
					CIDR:    pool1Cidr,
					Subnet:  "10.10.10.10",
				}
			})
			It("parse subnet err", func() {
				Expect(r.addIPPool(&ippool1).Error()).Should(Equal("invalid CIDR address: 10.10.10.10"))

			})
		})

		When("invalid gw", func() {
			BeforeEach(func() {
				ippool1.Spec = ipamv1alpha1.IPPoolSpec{
					Gateway: "10.10.10",
					CIDR:    pool1Cidr,
					Subnet:  pool1Subnet,
				}
			})
			It("parse gateway err", func() {
				Expect(r.addIPPool(&ippool1).Error()).Should(Equal("invalid ippool gateway ip 10.10.10"))
				Expect(r.subnets).Should(HaveKey(pool1Subnet))
				Expect(r.subnets[pool1Subnet].UnsortedList()).Should(ContainElements(pool1))
				Expect(r.gws).Should(HaveKey("10.10.10"))
				Expect(r.gws["10.10.10"].UnsortedList()).Should(ContainElements(pool1))

				Expect(iptCtrl.cidrs.Has(pool1Subnet)).Should(BeTrue())
				Expect(routeCtrl.cidrs.Has(pool1Subnet)).Should(BeTrue())

				gws, err := dumpLocalBrIcmpReply()
				Expect(err).ToNot(HaveOccurred())
				Expect(len(gws)).Should(Equal(0))

				subnets, err := dumpLocalBrArpProxy()
				Expect(err).ToNot(HaveOccurred())
				Expect(subnets).Should(ContainElements(pool1Subnet))
				subnets, err = dumpUplinkBrIPForward()
				Expect(err).ToNot(HaveOccurred())
				Expect(subnets).Should(ContainElements(pool1Subnet))
			})
		})
		When("add a exist subnet", func() {
			BeforeEach(func() {
				Expect(r.addIPPool(&ippool1)).ToNot(HaveOccurred())
			})
			It("success", func() {
				ippool2.Spec = ipamv1alpha1.IPPoolSpec{
					Gateway: "10.10.10.128",
					CIDR:    "10.10.10.128/25",
					Subnet:  "10.10.10.23/24",
				}
				Expect(r.addIPPool(&ippool2)).ToNot(HaveOccurred())
				Expect(r.subnets).Should(HaveKey(pool1Subnet))
				Expect(r.subnets[pool1Subnet].UnsortedList()).Should(ContainElements(pool1, pool2))

				gws, err := dumpLocalBrIcmpReply()
				Expect(err).ToNot(HaveOccurred())
				Expect(gws).Should(ContainElements(pool1Gw, "10.10.10.128"))

				subnets, err := dumpLocalBrArpProxy()
				Expect(err).ToNot(HaveOccurred())
				Expect(subnets).Should(HaveExactElements(pool1Subnet))
				subnets, err = dumpUplinkBrIPForward()
				Expect(err).ToNot(HaveOccurred())
				Expect(len(subnets)).Should(Equal(2))
				Expect(subnets).Should(ContainElements(pool1Subnet, gwIPPoolSubnet))
			})
		})
		When("add route failed", func() {
			BeforeEach(func() {
				routeCtrl.err = routeError
			})
			It("cache has been added", func() {
				Expect(r.addIPPool(&ippool1).Error()).Should(Equal(routeError.Error()))
				Expect(r.subnets).Should(HaveKey(pool1Subnet))
				Expect(r.subnets[pool1Subnet].UnsortedList()).Should(ContainElements(pool1))

				Expect(routeCtrl.cidrs.UnsortedList()).Should(HaveExactElements(pool1Subnet))
				Expect(iptCtrl.cidrs.UnsortedList()).Should(HaveExactElements(pool1Subnet))

				gws, err := dumpLocalBrIcmpReply()
				Expect(err).ToNot(HaveOccurred())
				Expect(gws).Should(ContainElements(pool1Gw))

				subnets, err := dumpLocalBrArpProxy()
				Expect(err).ToNot(HaveOccurred())
				Expect(subnets).Should(HaveExactElements(pool1Subnet))
				subnets, err = dumpUplinkBrIPForward()
				Expect(err).ToNot(HaveOccurred())
				Expect(len(subnets)).Should(Equal(2))
				Expect(subnets).Should(ContainElements(pool1Subnet, gwIPPoolSubnet))
			})
		})
		When("add iptables failed", func() {
			BeforeEach(func() {
				iptCtrl.err = iptError
			})
			It("cache has been added", func() {
				Expect(r.addIPPool(&ippool1).Error()).Should(Equal(iptError.Error()))
				Expect(r.subnets).Should(HaveKey(pool1Subnet))
				Expect(r.subnets[pool1Subnet].UnsortedList()).Should(ContainElements(pool1))

				Expect(iptCtrl.cidrs.UnsortedList()).Should(HaveExactElements(pool1Subnet))
				Expect(routeCtrl.cidrs.UnsortedList()).Should(HaveExactElements(pool1Subnet))

				gws, err := dumpLocalBrIcmpReply()
				Expect(err).ToNot(HaveOccurred())
				Expect(gws).Should(ContainElements(pool1Gw))

				subnets, err := dumpLocalBrArpProxy()
				Expect(err).ToNot(HaveOccurred())
				Expect(subnets).Should(HaveExactElements(pool1Subnet))
				subnets, err = dumpUplinkBrIPForward()
				Expect(err).ToNot(HaveOccurred())
				Expect(len(subnets)).Should(Equal(2))
				Expect(subnets).Should(ContainElements(pool1Subnet, gwIPPoolSubnet))
			})
		})
	})

	Context("del ippool", func() {
		BeforeEach(func() {
			resetErr()
			ippool1.Spec = ipamv1alpha1.IPPoolSpec{
				Gateway: pool1Gw,
				CIDR:    pool1Cidr,
				Subnet:  pool1Subnet,
			}
			Expect(r.addIPPool(&ippool1)).ToNot(HaveOccurred())
		})
		When("del ippool that it's subnet and gw is the same as other ippool", func() {
			BeforeEach(func() {
				ippool2.Spec = ipamv1alpha1.IPPoolSpec{
					Gateway: pool1Gw,
					CIDR:    pool1Cidr,
					Subnet:  pool1Subnet,
				}
				Expect(r.addIPPool(&ippool2)).ToNot(HaveOccurred())
				Expect(r.subnets[pool1Subnet].UnsortedList()).Should(ContainElements(pool1, pool2))
				Expect(r.gws[pool1Gw].UnsortedList()).Should(ContainElements(pool1, pool2))
			})
			It("route, iptables rule and ovs flow doesn't been deleted", func() {
				Expect(r.deleteIPPool(pool2)).ToNot(HaveOccurred())
				Expect(r.subnets[pool1Subnet].UnsortedList()).Should(ContainElements(pool1))
				Expect(r.gws[pool1Gw].UnsortedList()).Should(ContainElements(pool1))

				Expect(iptCtrl.cidrs.Has(pool1Subnet)).Should(BeTrue())
				Expect(routeCtrl.cidrs.Has(pool1Subnet)).Should(BeTrue())

				gws, err := dumpLocalBrIcmpReply()
				Expect(err).ToNot(HaveOccurred())
				Expect(gws).Should(ContainElements(pool1Gw))

				subnets, err := dumpLocalBrArpProxy()
				Expect(err).ToNot(HaveOccurred())
				Expect(subnets).Should(ContainElements(pool1Subnet))
				subnets, err = dumpUplinkBrIPForward()
				Expect(err).ToNot(HaveOccurred())
				Expect(subnets).Should(ContainElements(pool1Subnet, gwIPPoolSubnet))
			})
		})
		When("del iptables failed", func() {
			BeforeEach(func() {
				iptCtrl.err = iptError
			})
			It("ippool controllers cache doesn't update", func() {
				Expect(r.deleteIPPool(pool1).Error()).Should(Equal(iptError.Error()))
				Expect(r.subnets).Should(HaveKey(pool1Subnet))
				Expect(r.subnets[pool1Subnet].UnsortedList()).Should(ContainElements(pool1))

				By("iptables cidrs has been deleted")
				Expect(iptCtrl.cidrs.Len()).Should(Equal(0))
				By("route cidrs has been deleted")
				Expect(routeCtrl.cidrs.Len()).Should(Equal(0))

				By("ovs flows has been deleted")
				gws, err := dumpLocalBrIcmpReply()
				Expect(err).ToNot(HaveOccurred())
				Expect(len(gws)).Should(Equal(0))

				subnets, err := dumpLocalBrArpProxy()
				Expect(err).ToNot(HaveOccurred())
				Expect(len(subnets)).Should(Equal(0))
				subnets, err = dumpUplinkBrIPForward()
				Expect(err).ToNot(HaveOccurred())
				Expect(subnets).Should(HaveExactElements(gwIPPoolSubnet))
			})
		})
	})
})
