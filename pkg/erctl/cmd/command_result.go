package cmd

import "github.com/everoute/everoute/pkg/apis/rpc/v1alpha1"

func isSkipResult(result *v1alpha1.CommandResult) bool {
	return result != nil && result.GetCode() == v1alpha1.CommandResult_SKIP_NORMAL
}

func resultReason(result *v1alpha1.CommandResult) string {
	if result == nil {
		return ""
	}
	if result.GetReason() != "" {
		return result.GetReason()
	}
	return result.GetMessage()
}
