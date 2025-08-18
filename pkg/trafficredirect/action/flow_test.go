package action

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("flow", func() {
	BeforeEach(func() {
		cmd := fmt.Sprintf("ovs-vsctl add-br %s-policy", testBr1)
		_, err := executeCommand(cmd)
		g.Expect(err).ShouldNot(HaveOccurred())
		cmd = fmt.Sprintf("ovs-ofctl add-flow %s-policy 'cookie=0x2000000040000000,table=0,ip, priority=30 actions=drop'", testBr1)
		_, err = executeCommand(cmd)
		g.Expect(err).ShouldNot(HaveOccurred())
		cmd = fmt.Sprintf("ovs-ofctl add-flow %s-policy 'cookie=0x50000000,table=0, icmp, priority=100 actions=drop'", testBr1)
		_, err = executeCommand(cmd)
		g.Expect(err).ShouldNot(HaveOccurred())
		cmd = fmt.Sprintf("ovs-ofctl add-flow %s-policy 'cookie=0x2000000040000040,table=0, tcp, priority=100 actions=drop'", testBr1)
		_, err = executeCommand(cmd)
		g.Expect(err).ShouldNot(HaveOccurred())
	})

	AfterEach(func() {
		cmd := fmt.Sprintf("ovs-vsctl --if-exists del-br %s-policy", testBr1)
		_, err := executeCommand(cmd)
		g.Expect(err).ShouldNot(HaveOccurred())
	})

	Context("DelTRNicFlows", func() {
		It("should success", func() {
			err := DelTRNicFlows(testBr1)
			g.Expect(err).ShouldNot(HaveOccurred())
			cmd := fmt.Sprintf("ovs-ofctl dump-flows %s-policy 'cookie=0x50000000/-1'", testBr1)
			res, err := executeCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(res).Should(ContainSubstring("cookie=0x50000000"))
			cmd = fmt.Sprintf("ovs-ofctl dump-flows %s-policy 'cookie=0x2000000040000040/-1'", testBr1)
			res, err = executeCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(res).Should(ContainSubstring("cookie=0x2000000040000040"))
			cmd = fmt.Sprintf("ovs-ofctl dump-flows %s-policy 'cookie=0x2000000040000000/-1'", testBr1)
			res, err = executeCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(res).ShouldNot(ContainSubstring("cookie=0x2000000040000000"))
		})
	})

	Context("DelTRHealthyFlows", func() {
		It("should success", func() {
			err := DelTRHealthyFlows(testBr1)
			g.Expect(err).ShouldNot(HaveOccurred())
			cmd := fmt.Sprintf("ovs-ofctl dump-flows %s-policy 'cookie=0x50000000/-1'", testBr1)
			res, err := executeCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(res).Should(ContainSubstring("cookie=0x50000000"))
			cmd = fmt.Sprintf("ovs-ofctl dump-flows %s-policy 'cookie=0x2000000040000040/-1'", testBr1)
			res, err = executeCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(res).ShouldNot(ContainSubstring("cookie=0x2000000040000040"))
			cmd = fmt.Sprintf("ovs-ofctl dump-flows %s-policy 'cookie=0x2000000040000000/-1'", testBr1)
			res, err = executeCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(res).Should(ContainSubstring("cookie=0x2000000040000000"))
		})
	})
})
