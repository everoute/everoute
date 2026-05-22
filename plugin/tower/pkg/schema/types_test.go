package schema

import (
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"
)

func TestEverouteClusterGetAssociation(t *testing.T) {
	cluster := &EverouteCluster{
		AgentELFClusters: []AgentELFCluster{
			{LocalID: "cluster-without-vds"},
		},
		AgentELFVDSes: []AgentELFVDS{
			{
				ObjectMeta: ObjectMeta{ID: "vds-2"},
				Cluster:    ObjectReference{ID: "cluster-1"},
			},
			{
				ObjectMeta: ObjectMeta{ID: "vds-1"},
				Cluster:    ObjectReference{ID: "cluster-1"},
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
							Cluster: ObjectReference{ID: "cluster-1"},
						},
					},
					{
						VDS: AgentELFVDS{
							ObjectMeta: ObjectMeta{ID: "vds-4"},
							Cluster:    ObjectReference{ID: "cluster-2"},
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
		"cluster-1": sets.New("vds-1", "vds-2", "vds-3"),
		"cluster-2": sets.New("vds-4"),
	}

	if len(got) != len(want) {
		t.Fatalf("unexpected association length, got %d want %d: %v", len(got), len(want), got)
	}
	for clusterID, wantVDSes := range want {
		if !got[clusterID].Equal(wantVDSes) {
			t.Fatalf("unexpected vdses for cluster %s, got %v want %v", clusterID, got[clusterID], wantVDSes)
		}
	}
}
