/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package policyrule

import (
	"context"
	"flag"
	"fmt"
	"os"

	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/contiv/ofnet"
	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"

	networkpolicyv1alpha1 "github.com/smartxworks/lynx/pkg/apis/policyrule/v1alpha1"
	lynxctrl "github.com/smartxworks/lynx/pkg/controller"
	// +kubebuilder:scaffold:imports
)

// PolicyRuleReconciler reconciles a PolicyRule object
type PolicyRuleReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
	Agent  *ofnet.OfnetAgent
}

type PolicyRuleController struct {
	Controller controller.Controller
}

func InitManager(scheme *runtime.Scheme, setupLog logr.Logger) manager.Manager {
	var metricsAddr string
	var enableLeaderElection bool
	flag.StringVar(&metricsAddr, "metrics-addr", ":8080", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr,
		Port:               9443,
		LeaderElection:     enableLeaderElection,
		LeaderElectionID:   "f2274c76.lynx.smartx.com",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	return mgr
}

func NewPolicyRuleController(mgr manager.Manager, agent *ofnet.OfnetAgent) (*PolicyRuleController, error) {
	c, err := controller.New("networkpolicy-controller", mgr, controller.Options{
		Reconciler: &PolicyRuleReconciler{
			Client: mgr.GetClient(),
			Log:    ctrl.Log.WithName("PolicyRuleController").WithName("PolicyRule"),
			Scheme: mgr.GetScheme(),
			Agent:  agent,
		},
	})
	if err != nil {
		return nil, err
	}

	return &PolicyRuleController{
		Controller: c,
	}, err
}

func (c *PolicyRuleController) Run(stopChan <-chan struct{}, mgr manager.Manager, setupLog logr.Logger) {
	// +kubebuilder:scaffold:builder
	setupLog.Info("starting manager")
	if err := mgr.Start(stopChan); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

// +kubebuilder:rbac:groups=networkpolicy.lynx.smartx.com,resources=policyrules,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networkpolicy.lynx.smartx.com,resources=policyrules/status,verbs=get;update;patch

func (r *PolicyRuleReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("policyrule", req.NamespacedName)

	// your logic here
	policyRule := networkpolicyv1alpha1.PolicyRule{}
	if err := r.Get(ctx, req.NamespacedName, &policyRule); err != nil {
		log.Error(err, "unable to featch policyRule")

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if r.isNewPolicyRule(&policyRule) {
		return r.ProcessPolicyRuleAdd(log, ctx, &policyRule)
	}
	if r.isDeletePolicyRule(&policyRule) {
		return r.ProcessPolicyRuleDelete(log, ctx, &policyRule)
	}
	// PolicyRule update ?

	return ctrl.Result{}, nil
}

func (r *PolicyRuleReconciler) ProcessPolicyRuleAdd(log logr.Logger, ctx context.Context, policyRule *networkpolicyv1alpha1.PolicyRule) (ctrl.Result, error) {
	// Add finalizers to new policyRule
	policyRule.ObjectMeta.Finalizers = []string{lynxctrl.DependentsCleanFinalizer}
	err := r.Update(ctx, policyRule)
	if err != nil {
		klog.Errorf("failed to create policyRule %s : %s", policyRule.Name, err.Error())
		return ctrl.Result{}, err
	}

	// Process PolicyRuleList: convert it to ofnetPolicyRule, filter illegal PolicyRule; install ofnetPolicyRule flow
	rule := policyRule.Spec
	ipProtoNo, err := protocolToInt(rule.IpProtocol)
	if err != nil {
		log.Error(err, "unsupport ipProtocol %s in PolicyRule", rule.IpProtocol)
		// Mark policyRule as failed
	}

	ofnetPolicyRule := &ofnet.OfnetPolicyRule{
		RuleId:     rule.RuleId,
		Priority:   int(rule.Priority),
		SrcIpAddr:  rule.SrcIpAddr,
		DstIpAddr:  rule.DstIpAddr,
		IpProtocol: ipProtoNo,
		SrcPort:    rule.SrcPort,
		DstPort:    rule.DstPort,
		IcmpType:   rule.ICMPType,
		IcmpCode:   rule.ICMPCode,
		TcpFlags:   rule.TcpFlags,
		Action:     rule.Action,
	}

	datapath := r.Agent.GetDatapath()
	datapath.GetPolicyAgent().AddRuleToTier(ofnetPolicyRule, rule.Tier)
	// PolicyRule enforce statistics TODO

	return ctrl.Result{}, err
}

func (r *PolicyRuleReconciler) ProcessPolicyRuleDelete(log logr.Logger, ctx context.Context, policyRule *networkpolicyv1alpha1.PolicyRule) (ctrl.Result, error) {
	policyRule.ObjectMeta.Finalizers = []string{}
	err := r.Update(ctx, policyRule)
	if err != nil {
		klog.Errorf("failed to delete policyRule %s : %s", policyRule.Name, err.Error())
	}

	rule := policyRule.Spec
	ipProtoNo, err := protocolToInt(rule.IpProtocol)
	if err != nil {
		log.Error(err, "unsupport ipProtocol %s in PolicyRule", rule.IpProtocol)
		// Mark policyRule as failed
	}

	ofnetPolicyRule := &ofnet.OfnetPolicyRule{
		RuleId:     rule.RuleId,
		Priority:   int(rule.Priority),
		SrcIpAddr:  rule.SrcIpAddr,
		DstIpAddr:  rule.DstIpAddr,
		IpProtocol: ipProtoNo,
		SrcPort:    rule.SrcPort,
		DstPort:    rule.DstPort,
		IcmpType:   rule.ICMPType,
		IcmpCode:   rule.ICMPCode,
		TcpFlags:   rule.TcpFlags,
		Action:     rule.Action,
	}

	datapath := r.Agent.GetDatapath()
	datapath.GetPolicyAgent().DelRule(ofnetPolicyRule, nil)

	return ctrl.Result{}, err
}

func (r *PolicyRuleReconciler) isNewPolicyRule(policyRule *networkpolicyv1alpha1.PolicyRule) bool {
	return policyRule.ObjectMeta.DeletionTimestamp == nil &&
		len(policyRule.ObjectMeta.Finalizers) == 0
}

func (r *PolicyRuleReconciler) isDeletePolicyRule(policyRule *networkpolicyv1alpha1.PolicyRule) bool {
	return policyRule.ObjectMeta.DeletionTimestamp != nil
}

func (r *PolicyRuleReconciler) SetupWithManager(mgr ctrl.Manager, c controller.Controller) error {
	if mgr == nil {
		return fmt.Errorf("can't setup with nil manager")
	}

	c.Watch(&source.Kind{Type: &networkpolicyv1alpha1.PolicyRuleList{}}, &handler.Funcs{
		CreateFunc: r.addPolicyRule,
		UpdateFunc: r.updatePolicyRule,
		DeleteFunc: r.deletePolicyRule,
	})

	return nil
}

func (r *PolicyRuleReconciler) addPolicyRule(e event.CreateEvent, q workqueue.RateLimitingInterface) {
	// Add policyRule in policyRule list,
	policyRules, ok := e.Object.(*networkpolicyv1alpha1.PolicyRuleList)
	if !ok {
		klog.Errorf("addPolicyRule receive event %v with error object", e)
	}

	for _, policyrule := range policyRules.Items {
		q.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
			Namespace: metav1.NamespaceNone,
			Name:      policyrule.Name,
		}})
	}
}

func (r *PolicyRuleReconciler) updatePolicyRule(e event.UpdateEvent, q workqueue.RateLimitingInterface) {
	policyRuleList := []networkpolicyv1alpha1.PolicyRule{}
	newPolicyRule, ok1 := e.ObjectNew.(*networkpolicyv1alpha1.PolicyRule)
	if ok1 {
		policyRuleList = append(policyRuleList, *newPolicyRule)
	}
	oldPolicyRule, ok2 := e.ObjectOld.(*networkpolicyv1alpha1.PolicyRule)
	if ok2 {
		policyRuleList = append(policyRuleList, *oldPolicyRule)
	}
	// NOTE policyRule update is same as (policyRule delete + policyRule create). we should keep operate sequence

	for _, policyrule := range policyRuleList {
		q.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
			Name: policyrule.Name,
		}})
	}
}

func (r *PolicyRuleReconciler) deletePolicyRule(e event.DeleteEvent, q workqueue.RateLimitingInterface) {
	// Add policyRule in policyRule list,
	policyRules, ok := e.Object.(*networkpolicyv1alpha1.PolicyRuleList)
	if !ok {
		klog.Errorf("addPolicyRule receive event %v with error object", e)
	}

	for _, policyrule := range policyRules.Items {
		q.Add(ctrl.Request{NamespacedName: k8stypes.NamespacedName{
			Namespace: metav1.NamespaceNone,
			Name:      policyrule.Name,
		}})
	}
}

func protocolToInt(ipProtocol string) (uint8, error) {
	var protoNo uint8
	switch ipProtocol {
	case "ICMP":
		protoNo = 1
	case "TCP":
		protoNo = 6
	case "UDP":
		protoNo = 17
	default:
		err := fmt.Errorf("unsupport ipProtocol %s in policyRule", ipProtocol)
		return protoNo, err
	}
	return protoNo, nil
}
