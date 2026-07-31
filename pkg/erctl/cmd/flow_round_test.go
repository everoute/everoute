package cmd

import (
	"errors"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/everoute/everoute/pkg/apis/rpc/v1alpha1"
)

var _ = Describe("FlowRound", func() {
	It("returns error when datapath manager is unavailable", func() {
		originConnect := connectFlowRoundClient
		originGetStatus := getFlowRoundStatusRPC
		connectFlowRoundClient = func() error { return nil }
		getFlowRoundStatusRPC = func() (*v1alpha1.FlowRoundStatus, error) {
			return nil, errors.New("rpc error: code = Unknown desc = datapath manager is not available")
		}
		defer func() {
			connectFlowRoundClient = originConnect
			getFlowRoundStatusRPC = originGetStatus
		}()

		output := captureStdout(func() {
			Expect(printFlowRoundStatusFromAgent()).To(MatchError(ContainSubstring("datapath manager is not available")))
		})

		Expect(output).To(BeEmpty())
	})

	It("skips skip-global-policy-wait-normal when flow round runtime is unavailable", func() {
		originConnect := connectFlowRoundClient
		originSkip := skipGlobalPolicyWaitNormalRPC
		connectFlowRoundClient = func() error { return nil }
		skipGlobalPolicyWaitNormalRPC = func() (*v1alpha1.FlowRoundStatus, error) {
			return &v1alpha1.FlowRoundStatus{
				Result: &v1alpha1.CommandResult{
					Code:   v1alpha1.CommandResult_SKIP_NORMAL,
					Reason: "flow round runtime is not available",
				},
			}, nil
		}
		defer func() {
			connectFlowRoundClient = originConnect
			skipGlobalPolicyWaitNormalRPC = originSkip
		}()

		output := captureStdout(func() {
			Expect(skipGlobalPolicyWaitNormalCmd.RunE(skipGlobalPolicyWaitNormalCmd, nil)).To(Succeed())
		})

		Expect(output).To(ContainSubstring("flow round skip-global-policy-wait-normal: skipped"))
		Expect(output).To(ContainSubstring("reason: flow round runtime is not available"))
	})

	It("skips cleanup-previous-round when startup flow sync is not enabled", func() {
		originConnect := connectFlowRoundClient
		originCleanup := cleanupPreviousRoundRPC
		connectFlowRoundClient = func() error { return nil }
		cleanupPreviousRoundRPC = func() (*v1alpha1.FlowRoundStatus, error) {
			return &v1alpha1.FlowRoundStatus{
				Result: &v1alpha1.CommandResult{
					Code:   v1alpha1.CommandResult_SKIP_NORMAL,
					Reason: "startup flow sync is not enabled",
				},
			}, nil
		}
		defer func() {
			connectFlowRoundClient = originConnect
			cleanupPreviousRoundRPC = originCleanup
		}()

		output := captureStdout(func() {
			Expect(cleanupPreviousRoundCmd.RunE(cleanupPreviousRoundCmd, nil)).To(Succeed())
		})

		Expect(output).To(ContainSubstring("flow round cleanup-previous-round: skipped"))
		Expect(output).To(ContainSubstring("reason: startup flow sync is not enabled"))
	})

})
