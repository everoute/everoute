package service

import "sync"

type Backend struct {
	lock sync.RWMutex
	// ID is unique identifier of Backend, it should be set svcNamespace/svcName/protocol/port
	ID string
	// Eps is all backends of service every port
	Eps []EpInfo
}

type EpInfo struct {
	IP   string `json:"ip"`
	Port int32  `json:"port"`
	Node string `json:"node"`
}
