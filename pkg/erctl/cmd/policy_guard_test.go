package cmd

import (
	"bytes"
	"io"
	"os"
	"strconv"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/everoute/everoute/pkg/apis/rpc/v1alpha1"
)

var _ = Describe("PolicyGuard", func() {
	It("prints unavailable status instead of returning an error when policy guard is unavailable", func() {
		originConnect := connectPolicyGuardClient
		originGetStatus := getPolicyGuardStatus
		connectPolicyGuardClient = func() error { return nil }
		getPolicyGuardStatus = func() (*v1alpha1.PolicyGuardStatus, error) {
			return &v1alpha1.PolicyGuardStatus{
				Result: &v1alpha1.CommandResult{
					Code:   v1alpha1.CommandResult_SKIP_NORMAL,
					Reason: "micro-segmentation is disabled",
				},
			}, nil
		}
		defer func() {
			connectPolicyGuardClient = originConnect
			getPolicyGuardStatus = originGetStatus
		}()

		output := captureStdout(func() {
			Expect(printPolicyGuardStatus()).To(Succeed())
		})

		Expect(output).To(ContainSubstring("policy guard: unavailable"))
		Expect(output).To(ContainSubstring("reason: micro-segmentation is disabled"))
	})

	It("prints policy guard status when policy guard is available", func() {
		originConnect := connectPolicyGuardClient
		originGetStatus := getPolicyGuardStatus
		connectPolicyGuardClient = func() error { return nil }
		getPolicyGuardStatus = func() (*v1alpha1.PolicyGuardStatus, error) {
			return &v1alpha1.PolicyGuardStatus{
				MemoryEnabled:     true,
				MemoryBreakerOpen: false,
				MemoryThreshold:   123,
				RuleEnabled:       true,
				RuleEstimateLimit: 456,
			}, nil
		}
		defer func() {
			connectPolicyGuardClient = originConnect
			getPolicyGuardStatus = originGetStatus
		}()

		output := captureStdout(func() {
			Expect(printPolicyGuardStatus()).To(Succeed())
		})

		Expect(output).To(ContainSubstring("memory:"))
		Expect(output).To(ContainSubstring("enabled: true"))
		Expect(output).To(ContainSubstring("breaker-open: false"))
		Expect(output).To(ContainSubstring("threshold: 123"))
		Expect(output).To(ContainSubstring("rule:"))
		Expect(output).To(ContainSubstring("rule-limit: 456"))
	})

	It("skips memory-threshold set when policy guard is unavailable", func() {
		originConnect := connectPolicyGuardClient
		originSet := setPolicyMemoryThresholdRPC
		connectPolicyGuardClient = func() error { return nil }
		setPolicyMemoryThresholdRPC = func(uint64) (*v1alpha1.SetPolicyMemoryThresholdResponse, error) {
			return &v1alpha1.SetPolicyMemoryThresholdResponse{
				Result: &v1alpha1.CommandResult{
					Code:   v1alpha1.CommandResult_SKIP_NORMAL,
					Reason: "micro-segmentation is disabled",
				},
			}, nil
		}
		defer func() {
			connectPolicyGuardClient = originConnect
			setPolicyMemoryThresholdRPC = originSet
		}()

		output := captureStdout(func() {
			Expect(setPolicyMemoryThresholdCmd.RunE(setPolicyMemoryThresholdCmd, []string{"123"})).To(Succeed())
		})

		Expect(output).To(ContainSubstring("policy guard memory-threshold set 123: skipped"))
		Expect(output).To(ContainSubstring("reason: micro-segmentation is disabled"))
	})

	It("skips rule-limit set when policy guard is unavailable", func() {
		originConnect := connectPolicyGuardClient
		originSet := setPolicyRuleEstimateLimitRPC
		connectPolicyGuardClient = func() error { return nil }
		setPolicyRuleEstimateLimitRPC = func(uint64) (*v1alpha1.SetPolicyRuleEstimateLimitResponse, error) {
			return &v1alpha1.SetPolicyRuleEstimateLimitResponse{
				Result: &v1alpha1.CommandResult{
					Code:   v1alpha1.CommandResult_SKIP_NORMAL,
					Reason: "micro-segmentation is disabled",
				},
			}, nil
		}
		defer func() {
			connectPolicyGuardClient = originConnect
			setPolicyRuleEstimateLimitRPC = originSet
		}()

		output := captureStdout(func() {
			Expect(setPolicyRuleLimitCmd.RunE(setPolicyRuleLimitCmd, []string{"456"})).To(Succeed())
		})

		Expect(output).To(ContainSubstring("policy guard rule-limit set 456: skipped"))
		Expect(output).To(ContainSubstring("reason: micro-segmentation is disabled"))
	})

	It("skips guard enable when policy guard is unavailable", func() {
		originConnect := connectPolicyGuardClient
		originSet := setPolicyGuardEnabledRPC
		connectPolicyGuardClient = func() error { return nil }
		setPolicyGuardEnabledRPC = func(string, bool) (*v1alpha1.SetPolicyGuardEnabledResponse, error) {
			return &v1alpha1.SetPolicyGuardEnabledResponse{
				Result: &v1alpha1.CommandResult{
					Code:   v1alpha1.CommandResult_SKIP_NORMAL,
					Reason: "micro-segmentation is disabled",
				},
			}, nil
		}
		defer func() {
			connectPolicyGuardClient = originConnect
			setPolicyGuardEnabledRPC = originSet
		}()

		output := captureStdout(func() {
			Expect(setPolicyGuardEnabled(policyGuardMemory, true)).To(Succeed())
		})

		Expect(output).To(ContainSubstring("policy guard memory enable: skipped"))
		Expect(output).To(ContainSubstring("reason: micro-segmentation is disabled"))
	})

	It("keeps argument parse errors for setters", func() {
		output := captureStdout(func() {
			err := setPolicyMemoryThresholdCmd.RunE(setPolicyMemoryThresholdCmd, []string{"invalid"})
			Expect(err).To(HaveOccurred())
			_, parseErr := strconv.ParseUint("invalid", 10, 64)
			Expect(err.Error()).To(Equal(parseErr.Error()))
		})

		Expect(output).To(BeEmpty())
	})
})

func captureStdout(fn func()) string {
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	Expect(err).NotTo(HaveOccurred())

	os.Stdout = w
	defer func() {
		os.Stdout = oldStdout
	}()

	fn()

	Expect(w.Close()).To(Succeed())
	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	Expect(err).NotTo(HaveOccurred())
	Expect(r.Close()).To(Succeed())

	return buf.String()
}
