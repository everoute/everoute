package types

import (
	"fmt"

	"k8s.io/apimachinery/pkg/types"
)

type RscInCacheNotFoundErr struct {
	rscType string
	rscKey  types.NamespacedName
}

func NewRscInCacheNotFoundErr(rscType string, rscKey types.NamespacedName) error {
	return &RscInCacheNotFoundErr{
		rscType: rscType,
		rscKey:  rscKey,
	}
}

func (r *RscInCacheNotFoundErr) Error() string {
	return fmt.Sprintf("%s: %s not found", r.rscType, r.rscKey)
}

func (r *RscInCacheNotFoundErr) RscType() string {
	return r.rscType
}

func IsRscInCacheNotFoundErr(e error) bool {
	_, ok := e.(*RscInCacheNotFoundErr)
	return ok
}
