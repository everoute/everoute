package utils

import (
	"os"
	"os/exec"
	"testing"

	"github.com/everoute/everoute/pkg/constants"
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

func TestCurrentAgentNameFromEnv(t *testing.T) {
	t.Setenv(constants.AgentNodeNameENV, "node-from-env")
	currentAgentName = ""
	t.Cleanup(func() {
		currentAgentName = ""
	})

	InitCurrentAgentName()
	if got := CurrentAgentName(); got != "node-from-env" {
		t.Fatalf("CurrentAgentName() = %q, want %q", got, "node-from-env")
	}
}

func TestCurrentAgentNameInitOnce(t *testing.T) {
	t.Setenv(constants.AgentNodeNameENV, "node-init")
	currentAgentName = ""
	t.Cleanup(func() {
		currentAgentName = ""
	})

	InitCurrentAgentName()
	if got := CurrentAgentName(); got != "node-init" {
		t.Fatalf("CurrentAgentName() = %q, want %q", got, "node-init")
	}
}

func TestInitCurrentAgentNameFatalOnEmpty(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestInitCurrentAgentNameFatalOnEmptyHelper")
	cmd.Env = append(os.Environ(),
		"GO_WANT_HELPER_PROCESS=1",
		constants.AgentNodeNameENV+"=",
	)

	err := cmd.Run()
	if err == nil {
		t.Fatal("InitCurrentAgentName() should exit when NODE_NAME is empty")
	}
}

func TestInitCurrentAgentNameFatalOnEmptyHelper(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}

	currentAgentName = ""
	InitCurrentAgentName()
}

func TestCurrentAgentNameConcurrentRead(t *testing.T) {
	t.Setenv(constants.AgentNodeNameENV, "node-concurrent")
	currentAgentName = ""
	t.Cleanup(func() {
		currentAgentName = ""
	})

	InitCurrentAgentName()

	done := make(chan struct{}, 8)
	for i := 0; i < 8; i++ {
		go func() {
			if got := CurrentAgentName(); got != "node-concurrent" {
				t.Errorf("CurrentAgentName() = %q, want %q", got, "node-concurrent")
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}
