package resolver

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.

import (
	"context"

	"github.com/everoute/everoute/plugin/tower/pkg/schema"
	"github.com/everoute/everoute/plugin/tower/pkg/server/fake/graph/generated"
)

// EverouteCluster is the resolver for the everoute_cluster field.
func (r *agentELFClusterResolver) EverouteCluster(ctx context.Context, obj *schema.AgentELFCluster) (*schema.ObjectReference, error) {
	return &schema.ObjectReference{ID: obj.EverouteClusterRef.ID}, nil
}

// EverouteCluster is the resolver for the everoute_cluster field.
func (r *agentELFVDSResolver) EverouteCluster(ctx context.Context, obj *schema.AgentELFVDS) (*schema.ObjectReference, error) {
	return &schema.ObjectReference{ID: obj.EverouteClusterRef.ID}, nil
}

// Vms is the resolver for the vms field.
func (r *labelResolver) Vms(ctx context.Context, obj *schema.Label) ([]schema.VM, error) {
	vmList := make([]schema.VM, len(obj.VMs))

	for _, reference := range obj.VMs {
		vmList = append(vmList, schema.VM{ObjectMeta: schema.ObjectMeta(reference)})
	}

	return vmList, nil
}

// AgentELFCluster returns generated.AgentELFClusterResolver implementation.
func (r *Resolver) AgentELFCluster() generated.AgentELFClusterResolver {
	return &agentELFClusterResolver{r}
}

// AgentELFVDS returns generated.AgentELFVDSResolver implementation.
func (r *Resolver) AgentELFVDS() generated.AgentELFVDSResolver { return &agentELFVDSResolver{r} }

// Label returns generated.LabelResolver implementation.
func (r *Resolver) Label() generated.LabelResolver { return &labelResolver{r} }

type agentELFClusterResolver struct{ *Resolver }
type agentELFVDSResolver struct{ *Resolver }
type labelResolver struct{ *Resolver }
