package dpihealthy

import (
	"context"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	"github.com/everoute/everoute/pkg/constants/tr"
	"github.com/everoute/everoute/pkg/types"
)

func Run(ctx context.Context, f func(types.DPIStatus)) {
	p := ProcessHealthyCheck{
		process:    f,
		lastStatus: types.DPIUnknown,
	}
	wait.UntilWithContext(ctx, p.Do, tr.DPIHealthyCheckPeriod)
	klog.Infof("Success start the task of periodically check dpi healthy status, period: %v", tr.DPIHealthyCheckPeriod)
}

type ProcessHealthyCheck struct {
	process    func(types.DPIStatus)
	lastStatus types.DPIStatus
}

func (p *ProcessHealthyCheck) Do(_ context.Context) {
	curS := HealthyCheck()
	if curS != p.lastStatus {
		klog.Infof("Begin to update DPI status from %s to %s", p.lastStatus, curS)
		p.process(curS)
		klog.Infof("Success update DPI status from %s to %s", p.lastStatus, curS)
		p.lastStatus = curS
	}
}
