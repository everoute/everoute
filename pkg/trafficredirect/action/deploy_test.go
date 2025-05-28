package action

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/everoute/everoute/pkg/config"
	"github.com/everoute/everoute/pkg/types"
)

var _ = Describe("Reset", func() {
	Describe("deploy trafficredirect", func() {
		cfg := &config.AgentConfig{
			VdsConfigs: map[string]config.VdsConfig{
				"vds1": {
					BrideName: testBr1,
					TrafficRedirects: []config.TRConfig{
						{
							NicIn:  ifaceID0,
							NicOut: ifaceID1,
						},
					},
				},
			},
		}

		BeforeEach(func() {
			cmd := fmt.Sprintf("ovs-vsctl add-br %s -- add-port %s %s -- set interface %s external_ids='%s'", svcChainBr, svcChainBr, tap0, tap0, externalIDs0)
			_, err := excuteCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
			cmd = fmt.Sprintf("ovs-vsctl -- add-port %s %s -- set interface %s external_ids='%s'", svcChainBr, tap1, tap1, externalIDs1)
			_, err = excuteCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
			cmd = fmt.Sprintf("ovs-vsctl add-br %s-policy", testBr1)
			_, err = excuteCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
			cmd = fmt.Sprintf("ovs-ofctl add-flow %s-policy 'cookie=0x2000000040000000,table=0,ip, priority=30 actions=drop'", testBr1)
			_, err = excuteCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
			cmd = fmt.Sprintf("ovs-ofctl add-flow %s-policy 'cookie=0x50000000,table=0, icmp, priority=100 actions=drop'", testBr1)
			_, err = excuteCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
		})

		AfterEach(func() {
			cmd := fmt.Sprintf("ovs-vsctl --if-exists del-br %s-policy", testBr1)
			_, err := excuteCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
			cmd = fmt.Sprintf("ovs-vsctl --if-exists del-br %s", svcChainBr)
			_, err = excuteCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
		})

		It("run", func() {
			By("deploy success")
			err := Reset(cfg)
			g.Expect(err).ShouldNot(HaveOccurred())

			p, err := getPortInfo(tap0)
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(p).ShouldNot(BeNil())
			g.Expect(p.brName).Should(Equal(testBr1 + "-policy"))
			g.Expect(p.intfExternalIDs).Should(Equal(externalIDs0))
			g.Expect(p.intfIfaceID).Should(Equal(ifaceID0))
			c, err := getNicConfig(testBr1, types.NicIn)
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(c).ShouldNot(BeNil())
			g.Expect(c.IfaceID).Should(Equal(ifaceID0))
			g.Expect(c.PortName).Should(Equal(tap0))
			g.Expect(c.PortUUID).Should(Equal(p.uuid))

			p, err = getPortInfo(tap1)
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(p).ShouldNot(BeNil())
			g.Expect(p.brName).Should(Equal(testBr1 + "-policy"))
			g.Expect(p.intfExternalIDs).Should(Equal(externalIDs1))
			g.Expect(p.intfIfaceID).Should(Equal(ifaceID1))
			c, err = getNicConfig(testBr1, types.NicOut)
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(c).ShouldNot(BeNil())
			g.Expect(c.IfaceID).Should(Equal(ifaceID1))
			g.Expect(c.PortName).Should(Equal(tap1))
			g.Expect(c.PortUUID).Should(Equal(p.uuid))

			By("clear success")
			err = Reset(nil)
			g.Expect(err).ShouldNot(HaveOccurred())

			p, err = getPortInfo(tap0)
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(p).ShouldNot(BeNil())
			g.Expect(p.brName).Should(Equal(svcChainBr))
			g.Expect(p.intfExternalIDs).Should(Equal(externalIDs0))
			g.Expect(p.intfIfaceID).Should(Equal(ifaceID0))
			c, err = getNicConfig(testBr1, types.NicIn)
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(c).Should(BeNil())

			p, err = getPortInfo(tap1)
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(p).ShouldNot(BeNil())
			g.Expect(p.brName).Should(Equal(svcChainBr))
			g.Expect(p.intfExternalIDs).Should(Equal(externalIDs1))
			g.Expect(p.intfIfaceID).Should(Equal(ifaceID1))
			c, err = getNicConfig(testBr1, types.NicOut)
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(c).Should(BeNil())

			cmd := fmt.Sprintf("ovs-ofctl dump-flows %s-policy 'cookie=0x50000000/-1'", testBr1)
			res, err := excuteCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(res).Should(ContainSubstring("cookie=0x50000000"))
			cmd = fmt.Sprintf("ovs-ofctl dump-flows %s-policy 'cookie=0x2000000040000000/-1'", testBr1)
			res, err = excuteCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(res).ShouldNot(ContainSubstring("cookie=0x2000000040000000"))
		})
	})
})
