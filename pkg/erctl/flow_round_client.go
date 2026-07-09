package erctl

import (
	"context"

	emptypb "google.golang.org/protobuf/types/known/emptypb"

	"github.com/everoute/everoute/pkg/apis/rpc/v1alpha1"
)

func GetFlowRoundStatus() (*v1alpha1.FlowRoundStatus, error) {
	return ruleconn.GetFlowRoundStatus(context.Background(), &emptypb.Empty{})
}

func SkipGlobalPolicyWaitNormal() (*v1alpha1.FlowRoundStatus, error) {
	return ruleconn.SkipGlobalPolicyWaitNormal(context.Background(), &emptypb.Empty{})
}

func CleanupPreviousRound() (*v1alpha1.FlowRoundStatus, error) {
	return ruleconn.CleanupPreviousRound(context.Background(), &emptypb.Empty{})
}
