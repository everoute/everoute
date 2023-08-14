package k8s

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo"
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
		Expect(k8sClient.Create(ctx, &ns)).Should(Succeed())
	})

	Context("delete node", func() {
		BeforeEach(func() {	
			Expect(k8sClient.Create(ctx, &node)).Should(Succeed())
		})

		When("gw-ep endpoint exists", func() {
			BeforeEach(func() {
				ep := v1alpha1.Endpoint{
					ObjectMeta: metav1.ObjectMeta{
						Name: utils.GetGwEndpointName(nodeName),
						Namespace: GwEpNs,
					},
				}
				Expect(k8sClient.Create(ctx, &ep)).Should(Succeed())
			})

			It("should delete gw-ep endpoint when delete node", func() {
				Expect(k8sClient.Delete(ctx, &node)).Should(Succeed())
				epKey := k8stypes.NamespacedName{
					Namespace: GwEpNs,
					Name: utils.GetGwEndpointName(nodeName),
				}
				ep := v1alpha1.Endpoint{}
				Eventually(func() bool {
					err := k8sClient.Get(ctx, epKey, &ep)
					return err != nil && errors.IsNotFound(err)
				}, 2*time.Minute, interval).Should(BeTrue())
			})
		})
	})
})
