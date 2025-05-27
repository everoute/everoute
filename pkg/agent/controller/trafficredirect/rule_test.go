package trafficredirect

import (
	"reflect"
	"sync"
	"testing"

	"github.com/everoute/everoute/pkg/agent/datapath"
	"github.com/everoute/trafficredirect/api/trafficredirect/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
)

func TestLocalRule_DiffFromRuleCR(t *testing.T) {
	type fields struct {
		Egress  bool
		Ingress bool
		Match   RuleMatch
	}
	type args struct {
		r2 *v1alpha1.Rule
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "Different Egress",
			fields: fields{
				Egress:  true,
				Ingress: false,
				Match: RuleMatch{
					SrcMac: "src1",
					DstMac: "dst1",
				},
			},
			args: args{
				r2: &v1alpha1.Rule{
					Spec: v1alpha1.RuleSpec{
						Egress:  false,
						Ingress: false,
						Match: v1alpha1.RuleMatch{
							SrcMac: "src1",
							DstMac: "dst1",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "Different Ingress",
			fields: fields{
				Egress:  false,
				Ingress: true,
				Match: RuleMatch{
					SrcMac: "src1",
					DstMac: "dst1",
				},
			},
			args: args{
				r2: &v1alpha1.Rule{
					Spec: v1alpha1.RuleSpec{
						Egress:  false,
						Ingress: false,
						Match: v1alpha1.RuleMatch{
							SrcMac: "src1",
							DstMac: "dst1",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "Different Match",
			fields: fields{
				Egress:  false,
				Ingress: false,
				Match: RuleMatch{
					SrcMac: "src1",
					DstMac: "dst1",
				},
			},
			args: args{
				r2: &v1alpha1.Rule{
					Spec: v1alpha1.RuleSpec{
						Egress:  false,
						Ingress: false,
						Match: v1alpha1.RuleMatch{
							SrcMac: "src2",
							DstMac: "dst1",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "NoDiff",
			fields: fields{
				Egress:  false,
				Ingress: false,
				Match: RuleMatch{
					SrcMac: "src1",
					DstMac: "dst1",
				},
			},
			args: args{
				r2: &v1alpha1.Rule{
					Spec: v1alpha1.RuleSpec{
						Egress:  false,
						Ingress: false,
						Match: v1alpha1.RuleMatch{
							SrcMac: "src1",
							DstMac: "dst1",
						},
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &LocalRule{
				Egress:  tt.fields.Egress,
				Ingress: tt.fields.Ingress,
				Match:   tt.fields.Match,
			}
			if got := r.DiffFromRuleCR(tt.args.r2); got != tt.want {
				t.Errorf("LocalRule.DiffFromRuleCR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLocalRule_toDPTRRuleSpec(t *testing.T) {
	type fields struct {
		Egress  bool
		Ingress bool
		Match   RuleMatch
	}
	tests := []struct {
		name   string
		fields fields
		want   *datapath.DPTRRuleSpec
	}{
		{
			name: "Egress",
			fields: fields{
				Egress:  true,
				Ingress: false,
				Match: RuleMatch{
					SrcMac: "src1",
					DstMac: "dst1",
				},
			},
			want: &datapath.DPTRRuleSpec{
				SrcMac: "src1",
				DstMac: "dst1",
				Direct: datapath.DirEgress,
			},
		},
		{
			name: "Ingress",
			fields: fields{
				Ingress: true,
				Match: RuleMatch{
					SrcMac: "src1",
					DstMac: "dst1",
				},
			},
			want: &datapath.DPTRRuleSpec{
				SrcMac: "src1",
				DstMac: "dst1",
				Direct: datapath.DirIngress,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &LocalRule{
				Egress:  tt.fields.Egress,
				Ingress: tt.fields.Ingress,
				Match:   tt.fields.Match,
			}
			if got := r.toDPTRRuleSpec(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LocalRule.toDPTRRuleSpec() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ruleCache_get(t *testing.T) {
	type fields struct {
		cache map[types.NamespacedName]*LocalRule
		lock  sync.RWMutex
	}
	type args struct {
		k types.NamespacedName
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *LocalRule
	}{
		{
			name: "ExistingKey",
			fields: fields{
				cache: map[types.NamespacedName]*LocalRule{
					types.NamespacedName{Namespace: "ns1", Name: "name1"}: &LocalRule{},
				},
			},
			args: args{
				k: types.NamespacedName{Namespace: "ns1", Name: "name1"},
			},
			want: &LocalRule{},
		},
		{
			name: "NonExistingKey",
			fields: fields{
				cache: map[types.NamespacedName]*LocalRule{},
			},
			args: args{
				k: types.NamespacedName{Namespace: "ns1", Name: "name2"},
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := &ruleCache{
				cache: tt.fields.cache,
				lock:  tt.fields.lock,
			}
			if got := rc.get(tt.args.k); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ruleCache.get() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ruleCache_delete(t *testing.T) {
	type fields struct {
		cache map[types.NamespacedName]*LocalRule
		lock  sync.RWMutex
	}
	type args struct {
		k types.NamespacedName
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "ExistingKey",
			fields: fields{
				cache: map[types.NamespacedName]*LocalRule{
					types.NamespacedName{Namespace: "ns1", Name: "name1"}: &LocalRule{},
				},
			},
			args: args{
				k: types.NamespacedName{Namespace: "ns1", Name: "name1"},
			},
		},
		{
			name: "NonExistingKey",
			fields: fields{
				cache: map[types.NamespacedName]*LocalRule{},
			},
			args: args{
				k: types.NamespacedName{Namespace: "ns1", Name: "name2"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := &ruleCache{
				cache: tt.fields.cache,
				lock:  tt.fields.lock,
			}
			rc.delete(tt.args.k)
			if _, ok := rc.cache[tt.args.k]; ok {
				t.Errorf("Expected key %v to be deleted from cache", tt.args.k)
			}
		})
	}
}

func Test_ruleCache_add(t *testing.T) {
	type fields struct {
		cache map[types.NamespacedName]*LocalRule
		lock  sync.RWMutex
	}
	type args struct {
		k types.NamespacedName
		r *LocalRule
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		expAdd bool
	}{
		{
			name: "AddNil",
			fields: fields{
				cache: make(map[types.NamespacedName]*LocalRule),
			},
			args: args{
				k: types.NamespacedName{Namespace: "ns1", Name: "name1"},
				r: nil,
			},
			expAdd: false,
		},
		{
			name: "AddNewRule",
			fields: fields{
				cache: make(map[types.NamespacedName]*LocalRule),
			},
			args: args{
				k: types.NamespacedName{Namespace: "ns1", Name: "name1"},
				r: &LocalRule{},
			},
			expAdd: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := &ruleCache{
				cache: tt.fields.cache,
				lock:  tt.fields.lock,
			}
			rc.add(tt.args.k, tt.args.r)
			_, ok := rc.cache[tt.args.k]
			if tt.expAdd && !ok{
				t.Errorf("Expected key %v to be added to cache", tt.args.k)
			}
			if !tt.expAdd && ok {
				t.Errorf("Expected key %v not to be added to cache", tt.args.k)
			}
		})
	}
}

func Test_toLocalRule(t *testing.T) {
 type args struct {
  r *v1alpha1.Rule
 }
 tests := []struct {
  name string
  args args
  want *LocalRule
 }{
  {
   name: "FullRule",
   args: args{
    r: &v1alpha1.Rule{
     Spec: v1alpha1.RuleSpec{
      Egress: true,
      Ingress: false,
      Match: v1alpha1.RuleMatch{
       SrcMac: "src1",
       DstMac: "dst1",
      },
     },
    },
   },
   want: &LocalRule{
    Egress: true,
    Ingress: false,
    Match: RuleMatch{
     SrcMac: "src1",
     DstMac: "dst1",
    },
   },
  },
  {
   name: "MinimalRule",
   args: args{
    r: &v1alpha1.Rule{
     Spec: v1alpha1.RuleSpec{
      Egress: false,
      Ingress: true,
      Match: v1alpha1.RuleMatch{},
     },
    },
   },
   want: &LocalRule{
    Egress: false,
    Ingress: true,
    Match: RuleMatch{},
   },
  },
 }
 for _, tt := range tests {
  t.Run(tt.name, func(t *testing.T) {
   if got := toLocalRule(tt.args.r); !reflect.DeepEqual(got, tt.want) {
    t.Errorf("toLocalRule() = %v, want %v", got, tt.want)
   }
  })
 }
}