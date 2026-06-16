package schema

import (
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"
)

func TestEverouteClusterGetAssociation(t *testing.T) {
	cluster := &EverouteCluster{
		AgentELFVDSes: []AgentELFVDS{
			{
				ObjectMeta: ObjectMeta{ID: "vds-1"},
				Cluster:    ClusterReference{LocalID: "elf-1"},
			},
			{
				ObjectMeta: ObjectMeta{ID: "vds-without-cluster"},
			},
		},
		Status: EverouteClusterStatus{
			Agents: EverouteClusterAgentStatus{
				ManageVDSes: []EverouteClusterManagedVDS{
					{
						VDSID: "vds-3",
						VDS: AgentELFVDS{
							Cluster: ClusterReference{LocalID: "elf-1"},
						},
					},
					{
						VDS: AgentELFVDS{
							ObjectMeta: ObjectMeta{ID: "vds-4"},
							Cluster:    ClusterReference{LocalID: "elf-2"},
						},
					},
					{
						VDS: AgentELFVDS{
							ObjectMeta: ObjectMeta{ID: "vds-5"},
							Cluster:    ClusterReference{LocalID: "elf-3"},
						},
					},
					{
						VDSID: "vds-without-cluster",
					},
				},
			},
		},
	}

	got := cluster.GetAssociation()
	want := map[string]sets.Set[string]{
		"elf-1": sets.New("vds-1", "vds-3"),
		"elf-2": sets.New("vds-4"),
		"elf-3": sets.New("vds-5"),
	}

	if len(got) != len(want) {
		t.Fatalf("unexpected association length, got %d want %d: %v", len(got), len(want), got)
	}
	for clusterLocalID, wantVDSes := range want {
		if !got[clusterLocalID].Equal(wantVDSes) {
			t.Fatalf("unexpected vdses for cluster %s, got %v want %v", clusterLocalID, got[clusterLocalID], wantVDSes)
		}
	}
}
