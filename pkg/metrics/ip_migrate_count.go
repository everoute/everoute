package metrics

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/util/wait"
	klog "k8s.io/klog/v2"

	constants "github.com/everoute/everoute/pkg/constants/ms"
)

type IPMigrateCount struct {
	lock sync.RWMutex
	// key is ip, value is update time
	index      sync.Map
	data       *prometheus.CounterVec
	// key is ip, value is the vm to which the ip belongs to
	lastLowner sync.Map
}

func NewIPMigrateCount() *IPMigrateCount {
	return &IPMigrateCount{
		data: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: constants.MetricNamespace,
			Subsystem: constants.MetricSubSystem,
			Name:      constants.MetricIPMigrateCountName,
			Help:      "The count for changes vm nic which ip belongs",
		}, []string{constants.MetricIPLabel}),
	}
}

func (i *IPMigrateCount) Inc(ip, vm string) {
	i.lock.RLock()
	defer i.lock.RUnlock()

	last, _ := i.lastLowner.Swap(ip, vm)
	if last != nil {
		if last.(string) == vm {
			return
		}
	}
	l := make(map[string]string, 1)
	l[constants.MetricIPLabel] = ip
	i.data.With(l).Inc()
	i.index.Store(ip, time.Now())
}

func (i *IPMigrateCount) Run(ctx context.Context) {
	go wait.UntilWithContext(ctx, i.clean, 30*time.Minute)
}

func (i *IPMigrateCount) clean(context.Context) {
	i.lock.Lock()
	defer i.lock.Unlock()

	ipNums := 0
	timeNow := time.Now()
	delKey := []string{}
	i.index.Range(func(k, v interface{}) bool {
		ipNums++
		vTime := v.(time.Time)
		if vTime.Add(time.Hour).Before(timeNow) {
			delKey = append(delKey, k.(string))
		}
		return true
	})

	if ipNums > constants.MetricMaxIPNumInCache {
		klog.Info("Reset all IPMigrateCount")
		i.data.Reset()
		i.index = sync.Map{}
		i.lastLowner = sync.Map{}
		return
	}

	for _, ip := range delKey {
		klog.Infof("Reset IPMigrateCount for ip %s", ip)
		label := make(map[string]string, 1)
		label[constants.MetricIPLabel] = ip
		_ = i.data.Delete(label)
		i.index.Delete(ip)
		i.lastLowner.Delete(ip)
	}
}
