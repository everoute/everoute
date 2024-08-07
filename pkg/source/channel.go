package source

import (
	"context"
	"sync"

	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

type SyncCache interface {
	WaitForCacheSync(ctx context.Context) bool
}

var _ source.SyncingSource = &SyncingChannel{}

type SyncingChannel struct {
	Name string
	source.Channel
	SyncCaches []SyncCache
}

func (s *SyncingChannel) WaitForSync(ctx context.Context) error {
	var wg sync.WaitGroup
	for i := range s.SyncCaches {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s.SyncCaches[i].WaitForCacheSync(ctx)
		}(i)
	}
	wg.Wait()
	klog.Infof("Success sync cache for channel %s", s.Name)
	return nil
}
