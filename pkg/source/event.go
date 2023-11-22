package source

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

type Event struct {
	metav1.TypeMeta
	metav1.ObjectMeta
}

// DeepCopyObject is deep copy method for a event
func (e *Event) DeepCopyObject() runtime.Object {
	res := new(Event)
	res.Name = e.Name
	res.Namespace = e.Namespace

	return res
}

type SyncType string

const (
	// ReplayType sync event type is replay service proxy flow
	ReplayType SyncType = "replay"
)

// NewReplayEvent returns a replay flow event
func NewReplayEvent() event.GenericEvent {
	e := Event{}
	e.Namespace = string(ReplayType)

	return event.GenericEvent{Object: &e}
}

func NewResourceEvent(name, ns string) event.GenericEvent {
	e := Event{}
	e.Namespace = ns
	e.Name = name

	return event.GenericEvent{Object: &e}
}
