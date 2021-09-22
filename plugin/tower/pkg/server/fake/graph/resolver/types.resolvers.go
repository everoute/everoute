package resolver

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.

import (
	"context"

	"github.com/everoute/everoute/plugin/tower/pkg/schema"
	"github.com/everoute/everoute/plugin/tower/pkg/server/fake/graph/generated"
)

func (r *labelResolver) Vms(ctx context.Context, obj *schema.Label) ([]schema.VM, error) {
	vmList := make([]schema.VM, len(obj.VMs))

	for _, reference := range obj.VMs {
		vmList = append(vmList, schema.VM{ObjectMeta: schema.ObjectMeta(reference)})
	}

	return vmList, nil
}

// Label returns generated.LabelResolver implementation.
func (r *Resolver) Label() generated.LabelResolver { return &labelResolver{r} }

type labelResolver struct{ *Resolver }
