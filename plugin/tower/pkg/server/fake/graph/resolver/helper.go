package resolver

import "github.com/everoute/everoute/plugin/tower/pkg/server/fake/graph/model"

func matchObjectID(id string, where *model.ObjectWhereInput) bool {
	return where == nil || where.ID == nil || *where.ID == id
}
