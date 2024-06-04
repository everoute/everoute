package cache

const (
	SvcPortIndex = "SvcPortIndex"
	SvcIDIndex   = "SvcIDIndex"
)

func GenSvcPortIndex(svcNs, svcName, portName string) string {
	return svcNs + "/" + svcName + "/" + portName
}

func GenSvcPortIndexBySvcID(svcID, portName string) string {
	return svcID + "/" + portName
}

func GenSvcID(svcNS string, svcName string) string {
	return svcNS + "/" + svcName
}
