package trafficredirect

import (
	"sync"

	"github.com/everoute/trafficredirect/api/trafficredirect/v1alpha1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/everoute/everoute/pkg/agent/datapath"
)

type LocalRule struct {
	Match   RuleMatch
	Egress  bool
	Ingress bool
}

type RuleMatch struct {
	SrcMac string
	DstMac string
}

func (rm *RuleMatch) DiffFromRuleCR(rm2 *v1alpha1.RuleMatch) bool {
	if rm2 == nil {
		return true
	}
	if rm.DstMac != rm2.DstMac {
		return true
	}
	if rm.SrcMac != rm2.SrcMac {
		return true
	}
	return false
}

func (r *LocalRule) DiffFromRuleCR(r2 *v1alpha1.Rule) bool {
	if r2 == nil {
		return true
	}
	if r.Egress != r2.Spec.Egress {
		return true
	}
	if r.Ingress != r2.Spec.Ingress {
		return true
	}
	if r.Match.DiffFromRuleCR(&r2.Spec.Match) {
		return true
	}
	return false
}

func (r *LocalRule) toDPTRRuleSpec() *datapath.DPTRRuleSpec {
	res := &datapath.DPTRRuleSpec{
		SrcMac: r.Match.SrcMac,
		DstMac: r.Match.DstMac,
	}
	if r.Egress {
		res.Direct = datapath.DirEgress
	}
	if r.Ingress {
		res.Direct = datapath.DirIngress
	}
	return res
}

func toLocalRule(r *v1alpha1.Rule) *LocalRule {
	return &LocalRule{
        Ingress: r.Spec.Ingress,
        Egress:  r.Spec.Egress,
        Match: RuleMatch{
            SrcMac: r.Spec.Match.SrcMac,
            DstMac: r.Spec.Match.DstMac,
        },
    }
}

type ruleCache struct {
	cache map[types.NamespacedName]*LocalRule
	lock  sync.RWMutex
}

func newRuleCache() *ruleCache {
	return &ruleCache{
		cache: make(map[types.NamespacedName]*LocalRule),
	}
}

func (rc *ruleCache) get(k types.NamespacedName) *LocalRule {
	rc.lock.RLock()
	defer rc.lock.RUnlock()
	if rc.cache == nil {
		return nil
	}
	return rc.cache[k]
}

func (rc *ruleCache) delete(k types.NamespacedName) {
	rc.lock.Lock()
	defer rc.lock.Unlock()
	if rc.cache == nil {
		return
	}
	delete(rc.cache, k)
}

func (rc *ruleCache) add(k types.NamespacedName, r *LocalRule) {
	rc.lock.Lock()
	defer rc.lock.Unlock()
	if r == nil {
		return
	}
	if rc.cache == nil {
		rc.cache = make(map[types.NamespacedName]*LocalRule)
	}
	rc.cache[k] = r
}
