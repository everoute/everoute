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
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/contiv/ofnet"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"

	networkpolicyv1alpha1 "github.com/smartxworks/lynx/pkg/apis/policyrule/v1alpha1"
	// +kubebuilder:scaffold:imports
)

var (
	defaultRulePriority = 0
)

// PolicyRuleReconciler reconciles a PolicyRule object
type PolicyRuleReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Agent  *ofnet.OfnetAgent
}

type PolicyRuleController struct {
	Controller controller.Controller
}

func InitManager(scheme *runtime.Scheme) manager.Manager {
	var metricsAddr string
	var enableLeaderElection bool
	flag.StringVar(&metricsAddr, "metrics-addr", ":8080", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	klog.InitFlags(nil)
	flag.Parse()

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr,
		Port:               9443,
		LeaderElection:     enableLeaderElection,
		LeaderElectionID:   "f2274c76.lynx.smartx.com",
	})
	if err != nil {
		klog.Fatalf("unable to start manager: %s", err.Error())
		os.Exit(1)
	}

	return mgr
}

func NewPolicyRuleController(mgr manager.Manager, agent *ofnet.OfnetAgent) (*PolicyRuleController, error) {
	c, err := controller.New("networkpolicy-controller", mgr, controller.Options{
		Reconciler: &PolicyRuleReconciler{
			Client: mgr.GetClient(),
			Scheme: mgr.GetScheme(),
			Agent:  agent,
		},
	})
	if err != nil {
		klog.Fatalf("unable to create policyrule controller: %s", err.Error())
		return nil, err
	}

	return &PolicyRuleController{
		Controller: c,
	}, err
}

func (c *PolicyRuleController) Run(stopChan <-chan struct{}, mgr manager.Manager) {
	// +kubebuilder:scaffold:builder
	klog.Infof("start manager")
	if err := mgr.Start(stopChan); err != nil {
		klog.Fatalf("error while running manager: %s", err.Error())
		os.Exit(1)
	}
}

func (r *PolicyRuleReconciler) SetupWithManager(mgr ctrl.Manager, c controller.Controller) error {
	if mgr == nil {
		return fmt.Errorf("can't setup with nil manager")
	}

	c.Watch(&source.Kind{Type: &networkpolicyv1alpha1.PolicyRuleList{}}, &handler.Funcs{
		CreateFunc: r.addPolicyRule,
		DeleteFunc: r.deletePolicyRule,
	})

	return nil
}

// +kubebuilder:rbac:groups=networkpolicy.lynx.smartx.com,resources=policyrules,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networkpolicy.lynx.smartx.com,resources=policyrules/status,verbs=get;update;patch

func (r *PolicyRuleReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()

	// your logic here
	policyRule := networkpolicyv1alpha1.PolicyRule{}
	if err := r.Get(ctx, req.NamespacedName, &policyRule); err != nil {
		klog.Errorf("unable to fetch policyRule %s: %s", req.Name, err.Error())

		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// PolicyRule status update ?

	return ctrl.Result{}, nil
}

func (r *PolicyRuleReconciler) addPolicyRule(e event.CreateEvent, q workqueue.RateLimitingInterface) {
	policyRule, ok := e.Object.(*networkpolicyv1alpha1.PolicyRule)
	if !ok {
		klog.Errorf("addPolicyRule receive event %v with error object", e)
	}

	// Agent cache accept policyrule for restore from agent fail?? TODO

	// Process PolicyRuleList: convert it to ofnetPolicyRule, filter illegal PolicyRule; install ofnetPolicyRule flow
	rule := policyRule.Spec
	ipProtoNo, err := protocolToInt(rule.IpProtocol)
	if err != nil {
		klog.Errorf("unsupport ipProtocol %s in PolicyRule", rule.IpProtocol)
		// Mark policyRule as failed
	}

	var rulePriority int

	if rule.DefaultPolicyRule {
		rulePriority = defaultRulePriority
	} else {
		rulePriority = int(rule.Priority)
	}

	ruleAction, err := getRuleAction(rule.Action)
	if err != nil {
		klog.Errorf("unsupport ruleAction %s in PolicyRule", rule.Action)
	}

	ruleDirection, err := getRuleDirection(rule.Direction)
	if err != nil {
		klog.Errorf("unsupport ruleDirection %s in policyRule", rule.Direction)
	}
	ruleTier, err := getRuleTier(rule.Tier)
	if err != nil {
		klog.Errorf("unsupport ruleTier %s in policyRule.", rule.Tier)
	}

	ofnetPolicyRule := &ofnet.OfnetPolicyRule{
		RuleId:     rule.RuleId,
		Priority:   rulePriority,
		SrcIpAddr:  rule.SrcIpAddr,
		DstIpAddr:  rule.DstIpAddr,
		IpProtocol: ipProtoNo,
		SrcPort:    rule.SrcPort,
		DstPort:    rule.DstPort,
		TcpFlags:   rule.TcpFlags,
		Action:     ruleAction,
	}

	datapath := r.Agent.GetDatapath()
	err = datapath.GetPolicyAgent().AddRuleToTier(ofnetPolicyRule, ruleDirection, ruleTier)
	if err != nil {
		// Retry ? update policyRule enforce status for
	}
}

func (r *PolicyRuleReconciler) deletePolicyRule(e event.DeleteEvent, q workqueue.RateLimitingInterface) {
	// Add policyRule in policyRule list,
	policyRule, ok := e.Object.(*networkpolicyv1alpha1.PolicyRule)
	if !ok {
		klog.Errorf("addPolicyRule receive event %v with error object", e)
	}
	// Agent cache accept policyrule for restore from agent fail?? TODO

	rule := policyRule.Spec
	ipProtoNo, err := protocolToInt(rule.IpProtocol)

	if err != nil {
		klog.Errorf("unsupport ipProtocol %s in PolicyRule", rule.IpProtocol)
		// Mark policyRule as failed
	}

	var rulePriority int
	if rule.DefaultPolicyRule {
		rulePriority = defaultRulePriority
	} else {
		rulePriority = int(rule.Priority)
	}

	ruleAction, err := getRuleAction(rule.Action)
	if err != nil {
		klog.Errorf("unsupport ruleAction %s in PolicyRule", rule.Action)
	}

	ofnetPolicyRule := &ofnet.OfnetPolicyRule{
		RuleId:     rule.RuleId,
		Priority:   rulePriority,
		SrcIpAddr:  rule.SrcIpAddr,
		DstIpAddr:  rule.DstIpAddr,
		IpProtocol: ipProtoNo,
		SrcPort:    rule.SrcPort,
		DstPort:    rule.DstPort,
		TcpFlags:   rule.TcpFlags,
		Action:     ruleAction,
	}

	datapath := r.Agent.GetDatapath()
	err = datapath.GetPolicyAgent().DelRule(ofnetPolicyRule, nil)
	if err != nil {
		// Retry ? update policyRule enforce status for
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

func getRuleAction(ruleAction networkpolicyv1alpha1.RuleAction) (string, error) {
	var action string
	switch ruleAction {
	case networkpolicyv1alpha1.RuleActionAllow:
		action = "allow"
	case networkpolicyv1alpha1.RuleActionDrop:
		action = "deny"
	default:
		err := fmt.Errorf("unsupport ruleAction %s in policyrule.", ruleAction)
		return action, err
	}
	return action, nil
}

func getRuleDirection(ruleDir networkpolicyv1alpha1.RuleDirection) (uint8, error) {
	var direction uint8
	switch ruleDir {
	case networkpolicyv1alpha1.RuleDirectionIn:
		direction = 0
	case networkpolicyv1alpha1.RuleDirectionOut:
		direction = 1
	default:
		err := fmt.Errorf("unsupport ruleDirection %s in policyRule.", ruleDir)
		return direction, err
	}
	return direction, nil
}

func getRuleTier(ruleTier string) (uint8, error) {
	var tier uint8
	switch ruleTier {
	case "tier0":
		tier = 0
	case "tier1":
		tier = 1
	case "tier2":
		tier = 2
	default:
		err := fmt.Errorf("unsupport ruleTier %s in policyRule.", ruleTier)
		return tier, err
	}
	return tier, nil
}
