package endpoint

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"

	securityv1alpha1 "github.com/everoute/everoute/pkg/apis/security/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
)

var _ = Describe("strict mac feature", func() {
	epSrc := securityv1alpha1.Endpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ep",
			Namespace: strictMacNs,
			Labels:    make(map[string]string),
		},
		Spec: securityv1alpha1.EndpointSpec{
			StrictMac: false,
			Type:      securityv1alpha1.EndpointDynamic,
		},
	}
	epKey := types.NamespacedName{
		Namespace: strictMacNs,
		Name:      "ep",
	}

	AfterEach(func() {
		Expect(k8sClient.DeleteAllOf(ctx, &securityv1alpha1.Endpoint{}, client.InNamespace(strictMacNs))).ToNot(HaveOccurred())
	})

	It("create endpoint with sks-managed label", func() {
		By("create endpoint")
		ep := epSrc.DeepCopy()
		ep.Labels[constants.SksManagedLabelKey] = constants.SksManagedLabelValue
		ep.Labels["test"] = "test"
		Expect(k8sClient.Create(ctx, ep)).Should(Succeed())

		By("check StrictMac flag")
		Eventually(func(g Gomega) {
			ep := securityv1alpha1.Endpoint{}
			g.Expect(k8sClient.Get(ctx, epKey, &ep)).Should(Succeed())
			g.Expect(ep.Spec.StrictMac).Should(BeTrue())
		}, timeout, interval).Should(Succeed())
	})

	It("add sks-managed label to exist endpoint", func() {
		By("create endpoint without sks-managed label")
		ep := epSrc.DeepCopy()
		ep.Labels[constants.SksManagedLabelKey] = "test"
		ep.Labels["test"] = "test"
		Expect(k8sClient.Create(ctx, ep)).Should(Succeed())

		By("add sks-managed label")
		ep.Labels[constants.SksManagedLabelKey] = constants.SksManagedLabelValue
		Expect(k8sClient.Update(ctx, ep)).Should(Succeed())

		By("check StrictMac flag")
		Eventually(func(g Gomega) {
			ep := securityv1alpha1.Endpoint{}
			g.Expect(k8sClient.Get(ctx, epKey, &ep)).Should(Succeed())
			g.Expect(ep.Spec.StrictMac).Should(BeTrue())
		}, timeout, interval).Should(Succeed())
	})
})

func TestIsStrictMacLabel(t *testing.T) {
	tests := []struct {
		name string
		arg  map[string]string
		exp  bool
	}{
		{
			name: "nil label",
			arg:  nil,
			exp:  false,
		},
		{
			name: "only contain sks-managed key",
			arg:  makeMap("k1", "v1", constants.SksManagedLabelKey, "v2"),
			exp:  false,
		},
		{
			name: "only contain sks-managed value",
			arg:  makeMap("k1", "v1", "k2", constants.SksManagedLabelValue),
			exp:  false,
		},
		{
			name: "doesn't contain sks-managed label",
			arg:  makeMap("k1", "v1", "k2", "v2"),
			exp:  false,
		},
		{
			name: "contain sks-managed label",
			arg:  makeMap("k1", "v1", constants.SksManagedLabelKey, constants.SksManagedLabelValue),
			exp:  true,
		},
	}

	s := &StrictMacController{}
	for i := range tests {
		res := s.isStrictMacLabel(tests[i].arg)
		if res != tests[i].exp {
			t.Errorf("test %s failed, expect is %v, but real is %v", tests[i].name, tests[i].exp, res)
		}
	}
}

func TestPredicateCreate(t *testing.T) {
	tests := []struct {
		name string
		ep   *securityv1alpha1.Endpoint
		exp  bool
	}{
		{
			name: "strict mac is true",
			ep:   newEp(true, securityv1alpha1.EndpointDynamic, makeMap(constants.SksManagedLabelKey, constants.SksManagedLabelValue)),
			exp:  false,
		},
		{
			name: "static-ip type",
			ep:   newEp(false, securityv1alpha1.EndpointStaticIP, makeMap(constants.SksManagedLabelKey, constants.SksManagedLabelValue)),
			exp:  false,
		},
		{
			name: "static type",
			ep:   newEp(false, securityv1alpha1.EndpointStatic, makeMap(constants.SksManagedLabelKey, constants.SksManagedLabelValue)),
			exp:  false,
		},
		{
			name: "no label",
			ep:   newEp(false, securityv1alpha1.EndpointDynamic, makeMap()),
			exp:  false,
		},
		{
			name: "no match label",
			ep:   newEp(false, securityv1alpha1.EndpointDynamic, makeMap("k1", "v1", "k2", "v2")),
			exp:  false,
		},
		{
			name: "match all",
			ep:   newEp(false, securityv1alpha1.EndpointDynamic, makeMap(constants.SksManagedLabelKey, constants.SksManagedLabelValue)),
			exp:  true,
		},
	}

	s := &StrictMacController{}
	for i := range tests {
		res := s.predicateCreate(event.CreateEvent{Object: tests[i].ep})
		if res != tests[i].exp {
			t.Errorf("test %s failed, expect is %v, real is %v", tests[i].name, tests[i].exp, res)
		}
	}
}

func TestPredicateUpdate(t *testing.T) {
	tests := []struct {
		name  string
		oldEp *securityv1alpha1.Endpoint
		newEp *securityv1alpha1.Endpoint
		exp   bool
	}{
		{
			name:  "update other",
			oldEp: newEp(false, securityv1alpha1.EndpointDynamic, makeMap(constants.SksManagedLabelKey, constants.SksManagedLabelValue)),
			newEp: newEp(false, securityv1alpha1.EndpointDynamic, makeMap(constants.SksManagedLabelKey, constants.SksManagedLabelValue)),
			exp:   false,
		},
		{
			name:  "new endpoint stricMac is true",
			oldEp: newEp(false, securityv1alpha1.EndpointStatic, makeMap()),
			newEp: newEp(true, securityv1alpha1.EndpointDynamic, makeMap(constants.SksManagedLabelKey, constants.SksManagedLabelValue)),
			exp:   false,
		},
		{
			name:  "new endpoint type is static",
			oldEp: newEp(false, securityv1alpha1.EndpointDynamic, makeMap()),
			newEp: newEp(false, securityv1alpha1.EndpointStatic, makeMap(constants.SksManagedLabelKey, constants.SksManagedLabelValue)),
			exp:   false,
		},
		{
			name:  "new endpoint doesn't contain sks label",
			oldEp: newEp(false, securityv1alpha1.EndpointDynamic, makeMap(constants.SksManagedLabelKey, constants.SksManagedLabelValue)),
			newEp: newEp(false, securityv1alpha1.EndpointDynamic, makeMap(constants.SksManagedLabelKey, "kk")),
			exp:   false,
		},
		{
			name:  "add sks label to endpoint",
			oldEp: newEp(false, securityv1alpha1.EndpointDynamic, makeMap("k1", "v1")),
			newEp: newEp(false, securityv1alpha1.EndpointDynamic, makeMap(constants.SksManagedLabelKey, constants.SksManagedLabelValue)),
			exp:   true,
		},
	}

	s := &StrictMacController{}
	for i := range tests {
		res := s.predicateUpdate(event.UpdateEvent{
			ObjectOld: tests[i].oldEp,
			ObjectNew: tests[i].newEp,
		})

		if res != tests[i].exp {
			t.Errorf("test %s failed, expect is %v, real is %v", tests[i].name, tests[i].exp, res)
		}
	}
}
