package trafficredirect

import (
	"github.com/everoute/trafficredirect/api/trafficredirect/v1alpha1"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/everoute/everoute/pkg/agent/datapath"
)

var _ = Describe("test tr", func() {
	dstMac := "00:ee:ee:ef:1a:bc"
	expDpRuleSpec := datapath.DPTRRuleSpec{
		DstMac: dstMac,
		Direct: datapath.DirEgress,
	}
	ref1 := "default/rule1"
	AfterEach(func() {
		err := k8sClient.DeleteAllOf(ctx, &v1alpha1.Rule{}, client.InNamespace("default"))
		Expect(err).ShouldNot(HaveOccurred())
		Eventually(func(g Gomega) {
			validNoDpFlow(g)
		}, timeout, interval).Should(Succeed())
	})

	Context("tr rule", func() {
		BeforeEach(func() {
			tr := v1alpha1.Rule{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "rule1",
					Namespace: "default",
				},
				Spec: v1alpha1.RuleSpec{
					Direct: v1alpha1.Egress,
					Match: v1alpha1.RuleMatch{
						DstMac: dstMac,
					},
				},
			}
			Expect(k8sClient.Create(ctx, &tr, &client.CreateOptions{})).ShouldNot(HaveOccurred())
			Eventually(func(g Gomega) {
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "rule1"}, &v1alpha1.Rule{})).Should(Succeed())
			}, timeout, interval).Should(Succeed())
		})
		When("add", func() {
			It("should add ovs flow", func() {
				Eventually(func(g Gomega) {
					fid := validDpCache(g, expDpRuleSpec, sets.New[string](ref1), true)
					validDpFlow(g, "", dstMac, datapath.DirEgress, fid, true)
				}, timeout, interval).Should(Succeed())
			})

			When("add another rule with same spec", func() {
				oldFlowID := uint64(0)
				BeforeEach(func() {
					Eventually(func(g Gomega) {
						oldFlowID = validDpCache(g, expDpRuleSpec, sets.New[string](ref1), true)
						validDpFlow(g, "", dstMac, datapath.DirEgress, oldFlowID, true)
					}, timeout, interval).Should(Succeed())
					tr := v1alpha1.Rule{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "rule2",
							Namespace: "default",
						},
						Spec: v1alpha1.RuleSpec{
							Direct: v1alpha1.Egress,
							Match: v1alpha1.RuleMatch{
								DstMac: dstMac,
							},
						},
					}
					Expect(k8sClient.Create(ctx, &tr)).ShouldNot(HaveOccurred())
				})
				It("only update cache", func() {
					Eventually(func(g Gomega) {
						fid := validDpCache(g, expDpRuleSpec, sets.New[string](ref1, "default/rule2"), true)
						g.Expect(fid).Should(Equal(oldFlowID))
						validDpFlow(g, "", dstMac, datapath.DirEgress, fid, true)
					}, timeout, interval).Should(Succeed())
				})
			})
		})

		When("update", func() {
			It("update dst mac value", func() {
				tr := v1alpha1.Rule{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "rule1"}, &tr)).Should(Succeed())
				tr.Spec.Match.DstMac = "fe:f6:ee:a3:aa:b5"
				Expect(k8sClient.Update(ctx, &tr)).Should(Succeed())
				expDpRuleSpec2 := expDpRuleSpec
				expDpRuleSpec2.DstMac = "fe:f6:ee:a3:aa:b5"
				Eventually(func(g Gomega) {
					validDpCache(g, expDpRuleSpec, nil, false)
					fid := validDpCache(g, expDpRuleSpec2, sets.New[string](ref1), true)
					validDpFlow(g, "", "fe:f6:ee:a3:aa:b5", datapath.DirEgress, fid, true)
					validDpFlow(g, "", dstMac, datapath.DirEgress, 0, false)
				}, timeout, interval).Should(Succeed())
			})
			It("update direct", func() {
				tr := v1alpha1.Rule{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "rule1"}, &tr)).Should(Succeed())
				tr.Spec.Direct = v1alpha1.Ingress
				Expect(k8sClient.Update(ctx, &tr)).Should(Succeed())
				expDpRuleSpec2 := expDpRuleSpec
				expDpRuleSpec2.Direct = datapath.DirIngress
				Eventually(func(g Gomega) {
					validDpCache(g, expDpRuleSpec, nil, false)
					fid := validDpCache(g, expDpRuleSpec2, sets.New[string](ref1), true)
					validDpFlow(g, "", dstMac, datapath.DirIngress, fid, true)
					validDpFlow(g, "", dstMac, datapath.DirEgress, 0, false)
				}, timeout, interval).Should(Succeed())
			})

			It("update match", func() {
				tr := v1alpha1.Rule{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "rule1"}, &tr)).Should(Succeed())
				tr.Spec.Match.SrcMac = "f3:f3:f3:f3:f3:f3"
				Expect(k8sClient.Update(ctx, &tr)).Should(Succeed())
				expDpRuleSpec2 := expDpRuleSpec
				expDpRuleSpec2.SrcMac = "f3:f3:f3:f3:f3:f3"
				Eventually(func(g Gomega) {
					validDpCache(g, expDpRuleSpec, nil, false)
					fid := validDpCache(g, expDpRuleSpec2, sets.New[string](ref1), true)
					validDpFlow(g, "f3:f3:f3:f3:f3:f3", dstMac, datapath.DirEgress, fid, true)
					validDpFlow(g, "", dstMac, datapath.DirEgress, 0, false)
				}, timeout, interval).Should(Succeed())
			})
		})

		When("delete", func() {
			It("delete flow", func() {
				oldFlowID := uint64(0)
				Eventually(func(g Gomega) {
					oldFlowID = validDpCache(g, expDpRuleSpec, sets.New[string](ref1), true)
					validDpFlow(g, "", dstMac, datapath.DirEgress, oldFlowID, true)
				}, timeout, interval).Should(Succeed())
				tr := v1alpha1.Rule{}
				Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "rule1"}, &tr)).Should(Succeed())
				Expect(k8sClient.Delete(ctx, &tr)).Should(Succeed())
				Eventually(func(g Gomega) {
					validDpCache(g, expDpRuleSpec, nil, false)
					g.Expect(dpMgr.FlowIDToTRRules).ShouldNot(HaveKey(oldFlowID))
					validDpFlow(g, "", dstMac, datapath.DirEgress, oldFlowID, false)
				}, timeout, interval).Should(Succeed())
			})
			When("two rules with different spec", func() {
				oldFlowID := uint64(0)
				expDpRuleSpec2 := expDpRuleSpec
				expDpRuleSpec2.DstMac = ""
				expDpRuleSpec2.SrcMac = dstMac
				BeforeEach(func() {
					tr := v1alpha1.Rule{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "rule2",
							Namespace: "default",
						},
						Spec: v1alpha1.RuleSpec{
							Direct: v1alpha1.Egress,
							Match: v1alpha1.RuleMatch{
								SrcMac: dstMac,
							},
						},
					}
					Expect(k8sClient.Create(ctx, &tr)).ShouldNot(HaveOccurred())
					Eventually(func(g Gomega) {
						oldFlowID1 := validDpCache(g, expDpRuleSpec, sets.New[string](ref1), true)
						validDpFlow(g, "", dstMac, datapath.DirEgress, oldFlowID1, true)
						oldFlowID = validDpCache(g, expDpRuleSpec2, sets.New[string]("default/rule2"), true)
						validDpFlow(g, dstMac, "", datapath.DirEgress, oldFlowID, true)
					}, timeout, interval).Should(Succeed())
				})

				It("only delete one rule flow", func() {
					tr := v1alpha1.Rule{}
					Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "rule1"}, &tr)).Should(Succeed())
					Expect(k8sClient.Delete(ctx, &tr)).Should(Succeed())
					Eventually(func(g Gomega) {
						validDpCache(g, expDpRuleSpec, nil, false)
						validDpFlow(g, "", dstMac, datapath.DirEgress, 0, false)
						fid := validDpCache(g, expDpRuleSpec2, sets.New[string]("default/rule2"), true)
						g.Expect(fid).Should(Equal(oldFlowID))
						validDpFlow(g, dstMac, "", datapath.DirEgress, fid, true)
					}, timeout, interval).Should(Succeed())
				})
			})
			When("exists two rules with same spec", func() {
				BeforeEach(func() {
					tr := v1alpha1.Rule{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "rule2",
							Namespace: "default",
						},
						Spec: v1alpha1.RuleSpec{
							Direct: v1alpha1.Egress,
							Match: v1alpha1.RuleMatch{
								DstMac: dstMac,
							},
						},
					}
					Expect(k8sClient.Create(ctx, &tr)).ShouldNot(HaveOccurred())
					Eventually(func(g Gomega) {
						fid := validDpCache(g, expDpRuleSpec, sets.New[string](ref1, "default/rule2"), true)
						validDpFlow(g, "", dstMac, datapath.DirEgress, fid, true)
					}, timeout, interval).Should(Succeed())
				})

				It("only update cache", func() {
					tr := v1alpha1.Rule{}
					Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "rule1"}, &tr)).Should(Succeed())
					Expect(k8sClient.Delete(ctx, &tr)).Should(Succeed())
					Eventually(func(g Gomega) {
						fid := validDpCache(g, expDpRuleSpec, sets.New[string]("default/rule2"), true)
						validDpFlow(g, "", dstMac, datapath.DirEgress, fid, true)
					}, timeout, interval).Should(Succeed())
				})
			})
		})
	})
})
