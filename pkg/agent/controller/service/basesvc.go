package service

import (
	"sync"

	corev1 "k8s.io/api/core/v1"
)

type BaseSvc struct {
	lock sync.RWMutex
	// ID is unique identifier of BaseSvc, it should be set svcNamespace/svcName
	ID      string
	SvcType corev1.ServiceType

	ClusterIPs []string
	Ports      []Port

	ExternalTrafficPolicy string
	InternalTrafficPolicy string

	SessionAffinity corev1.ServiceAffinity
	// SessionAffinityTimeout， the unit is seconds
	SessionAffinityTimeout int32
}

type Port struct {
	// Name represents the associated name with this Port number.
	Name string
	// Protocol for port. Must be UDP, TCP  TODO not icmp webhook
	Protocol corev1.Protocol
	// Port represents the ClusterIP Service Port number.
	Port int32
	// Nodeport represents the NodePort Service NodePort number.
	NodePort int32
}
