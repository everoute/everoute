package proxy

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

// SyncEvent is struct of proxy sync event
type SyncEvent struct {
	metav1.TypeMeta
	metav1.ObjectMeta
}

type syncType string

const (
	// ReplayType sync event type is replay service proxy flow
	ReplayType syncType = "replay"
)

// DeepCopyObject is deep copy method for a event
func (e *SyncEvent) DeepCopyObject() runtime.Object {
	res := new(SyncEvent)
	res.Name = e.Name
	res.Namespace = e.Namespace

	return res
}

// NewReplayEvent returns a replay flow event
func NewReplayEvent() event.GenericEvent {
	e := SyncEvent{}
	e.Namespace = string(ReplayType)

	return event.GenericEvent{Meta: &e.ObjectMeta, Object: &e}
}
