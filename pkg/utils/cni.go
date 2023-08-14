package utils

import (
	"github.com/everoute/everoute/pkg/constants"
)

func GetGwEndpointName(nodeName string) string {
	return constants.GwEndpointName + "-" + nodeName
}
