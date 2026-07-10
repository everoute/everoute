package k8s

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/utils"
)

var _ = Describe("node controller test", func() {
	ctx := context.Background()
	nodeName := "node01"
	node := corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeName,
		},
	}

	BeforeEach(func() {
		ns := corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: GwEpNs,
			},
		}
		err := k8sClient.Create(ctx, &ns)
		Expect(err == nil || errors.IsAlreadyExists(err)).Should(BeTrue())
	})

	Context("delete node", func() {
		BeforeEach(func() {
			Expect(k8sClient.Create(ctx, &node)).Should(Succeed())
		})

		When("gw-ep endpoint exists", func() {
			BeforeEach(func() {
				ep := v1alpha1.Endpoint{
					ObjectMeta: metav1.ObjectMeta{
						Name:      utils.GetGwEndpointName(nodeName),
						Namespace: GwEpNs,
					},
				}
				Expect(k8sClient.Create(ctx, &ep)).Should(Succeed())
			})

			It("should delete gw-ep endpoint when delete node", func() {
				Expect(k8sClient.Delete(ctx, &node)).Should(Succeed())
				epKey := k8stypes.NamespacedName{
					Namespace: GwEpNs,
					Name:      utils.GetGwEndpointName(nodeName),
				}

				Eventually(func(g Gomega) {
					ep := v1alpha1.Endpoint{}
					err2 := k8sClient.Get(ctx, epKey, &ep)
					g.Expect(err2).ShouldNot(BeNil())
					g.Expect(errors.IsNotFound(err2)).Should(BeTrue())
				}, timeout, interval).Should(Succeed())
			})
		})
	})

	Context("cleanup stale gw endpoint by endpoint watch", func() {
		When("node doesn't exist", func() {
			BeforeEach(func() {
				ep := v1alpha1.Endpoint{
					ObjectMeta: metav1.ObjectMeta{
						Name:      utils.GetGwEndpointName(nodeName),
						Namespace: GwEpNs,
					},
				}
				Expect(k8sClient.Create(ctx, &ep)).Should(Succeed())
			})

			It("should delete stale gw-ep endpoint", func() {
				epKey := k8stypes.NamespacedName{
					Namespace: GwEpNs,
					Name:      utils.GetGwEndpointName(nodeName),
				}
				Eventually(func(g Gomega) {
					ep := v1alpha1.Endpoint{}
					err := k8sClient.Get(ctx, epKey, &ep)
					g.Expect(err).ShouldNot(BeNil())
					g.Expect(errors.IsNotFound(err)).Should(BeTrue())
				}, timeout, interval).Should(Succeed())
			})
		})

		When("node exists", func() {
			BeforeEach(func() {
				node = corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodeName,
					},
				}
				Expect(k8sClient.Create(ctx, &node)).Should(Succeed())
				ep := v1alpha1.Endpoint{
					ObjectMeta: metav1.ObjectMeta{
						Name:      utils.GetGwEndpointName(nodeName),
						Namespace: GwEpNs,
					},
				}
				Expect(k8sClient.Create(ctx, &ep)).Should(Succeed())
			})

			It("should keep gw-ep endpoint", func() {
				epKey := k8stypes.NamespacedName{
					Namespace: GwEpNs,
					Name:      utils.GetGwEndpointName(nodeName),
				}
				Consistently(func() error {
					ep := v1alpha1.Endpoint{}
					return k8sClient.Get(ctx, epKey, &ep)
				}, interval*3, interval).Should(Succeed())
			})
		})
	})
})
