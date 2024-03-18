package utils

import (
	"testing"
)

func makeMap(kvs ...string) map[string]string {
	m := make(map[string]string)
	i := 0
	for i < len(kvs) {
		m[kvs[i]] = kvs[i+1]
		i += 2
	}

	return m
}

func TestIsK8sLabelDiff(t *testing.T) {
	tests := []struct {
		name string
		l1   map[string]string
		l2   map[string]string
		exp  bool
	}{
		{
			name: "same with none value",
			l1:   makeMap("k1", "v1", "k2", ""),
			l2:   makeMap("k2", "", "k1", "v1"),
			exp:  false,
		},
		{
			name: "same",
			l1:   makeMap("k1", "v1", "k2", "v2"),
			l2:   makeMap("k2", "v2", "k1", "v1"),
			exp:  false,
		},
		{
			name: "difference len",
			l1:   makeMap("k1", "v1", "k2", "v2"),
			l2:   makeMap("k2", "v2", "k1", "v1", "k3", "v3"),
			exp:  true,
		},
		{
			name: "difference key",
			l1:   makeMap("k1", "v1", "k3", ""),
			l2:   makeMap("k2", "", "k1", "v1"),
			exp:  true,
		},
		{
			name: "difference value",
			l1:   makeMap("k1", "v5", "k3", ""),
			l2:   makeMap("k2", "", "k1", "v1"),
			exp:  true,
		},
		{
			name: "difference len and value",
			l1:   makeMap("k1", "v1", "k2", "v2"),
			l2:   makeMap("k2", "v2", "k1", "v1", "k3", ""),
			exp:  true,
		},
		{
			name: "same for nil",
			l1:   nil,
			l2:   map[string]string{},
			exp:  false,
		},
		{
			name: "different for one is nil",
			l1:   nil,
			l2:   makeMap("k1", "v1", "k2", "v2"),
			exp:  true,
		},
	}

	for i := range tests {
		res := IsK8sLabelDiff(tests[i].l1, tests[i].l2)
		if res != tests[i].exp {
			t.Errorf("test %s failed, real is %v, expect is %v", tests[i].name, res, tests[i].exp)
		}
	}
}
