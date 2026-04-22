package resolver

import "github.com/everoute/everoute/plugin/tower/pkg/server/fake/graph/model"

func matchesWhereForObjectID(id string, where *model.ObjectWhereInput) bool {
	return where == nil || where.ID == nil || *where.ID == id
}
