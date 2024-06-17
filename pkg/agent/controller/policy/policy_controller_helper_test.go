package policy

import (
	"fmt"
	"testing"

	"k8s.io/apimachinery/pkg/types"

	ertypes "github.com/everoute/everoute/pkg/types"
)

func TestIsGroupMembersNotFoundErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		exp  bool
	}{
		{
			name: "groupmembers err",
			err:  NewGroupMembersNotFoundErr("test"),
			exp:  true,
		},
		{
			name: "other rsInCacheNotFoundErr",
			err:  ertypes.NewRscInCacheNotFoundErr("test", types.NamespacedName{Namespace: "ns", Name: "name"}),
			exp:  false,
		},
		{
			name: "other err",
			err:  fmt.Errorf("test groupmembers err"),
			exp:  false,
		},
	}

	for _, c := range cases {
		res := IsGroupMembersNotFoundErr(c.err)
		if res != c.exp {
			t.Errorf("test %s failed, exp is %v, real is %v", c.name, c.exp, res)
		}
	}
}
