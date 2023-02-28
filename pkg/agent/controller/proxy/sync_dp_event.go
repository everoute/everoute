package proxy

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

type ProxySyncEvent struct {
	metav1.TypeMeta
	metav1.ObjectMeta
}

type proxySyncType string

const (
	ReplayType proxySyncType = "replay"
)

func (e *ProxySyncEvent) DeepCopyObject() runtime.Object {
	res := new(ProxySyncEvent)
	res.Name = e.Name
	res.Namespace = e.Namespace

	return res
}

func NewReplayEvent() event.GenericEvent {
	e := ProxySyncEvent{}
	e.Namespace = string(ReplayType)

	return event.GenericEvent{Meta: &e.ObjectMeta, Object: &e}
}
