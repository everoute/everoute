package action

import (
	"fmt"
	"strings"

	"github.com/agiledragon/gomonkey/v2"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/everoute/everoute/pkg/types"
)

var _ = Describe("mount unit test", func() {
	Describe("getPortInfo", func() {
		var patches *gomonkey.Patches
		var fakeCmdOutput string

		BeforeEach(func() {
			patches = gomonkey.NewPatches()

			// 默认 mock 成功返回 3 行结果
			fakeCmdOutput = "uuid1\nport1\n[intf1]"

			patches.ApplyFunc(excuteCommand, func(cmd string) (string, error) {
				if strings.Contains(cmd, "port-to-br") {
					return "br-test", nil
				}
				return fakeCmdOutput, nil
			})
			patches.ApplyFunc(getInterfaceExternalIDs, func(id string) (string, error) {
				return "external-id", nil
			})
			patches.ApplyFunc(getIfaceID, func(id string) (string, error) {
				return "iface-id", nil
			})
		})

		AfterEach(func() {
			patches.Reset()
		})

		It("returns nil if excuteCommand fails", func() {
			patches.ApplyFunc(excuteCommand, func(string) (string, error) {
				return "", fmt.Errorf("failed command")
			})
			port, err := getPortInfo("eth0")
			Expect(port).To(BeNil())
			Expect(err).To(HaveOccurred())
		})

		It("returns nil if excuteCommand returns empty", func() {
			fakeCmdOutput = ""
			port, err := getPortInfo("eth0")
			Expect(port).To(BeNil())
			Expect(err).To(BeNil())
		})

		It("returns error if result line count is not 3", func() {
			fakeCmdOutput = "uuid\nportonly"
			port, err := getPortInfo("eth0")
			Expect(port).To(BeNil())
			Expect(err).To(HaveOccurred())
		})

		It("returns error if interfaces length != 1", func() {
			fakeCmdOutput = "uuid1\nport1\n[intf1,intf2]"
			port, err := getPortInfo("eth0")
			Expect(port).To(BeNil())
			Expect(err).To(HaveOccurred())
		})

		It("returns error if getInterfaceExternalIDs fails", func() {
			patches.ApplyFunc(getInterfaceExternalIDs, func(string) (string, error) {
				return "", fmt.Errorf("failed")
			})
			port, err := getPortInfo("eth0")
			Expect(port).To(BeNil())
			Expect(err).To(HaveOccurred())
		})

		It("returns error if getIfaceID fails", func() {
			patches.ApplyFunc(getIfaceID, func(string) (string, error) {
				return "", fmt.Errorf("failed")
			})
			port, err := getPortInfo("eth0")
			Expect(port).To(BeNil())
			Expect(err).To(HaveOccurred())
		})

		It("returns error if second excuteCommand fails", func() {
			patches.ApplyFunc(excuteCommand, func(cmd string) (string, error) {
				if strings.Contains(cmd, "port-to-br") {
					return "", fmt.Errorf("fail")
				}
				return fakeCmdOutput, nil
			})
			port, err := getPortInfo("eth0")
			Expect(port).To(BeNil())
			Expect(err).To(HaveOccurred())
		})

		It("returns port struct successfully", func() {
			port, err := getPortInfo("eth0")
			Expect(err).To(BeNil())
			Expect(port).ToNot(BeNil())
			Expect(port.name).To(Equal("port1"))
			Expect(port.intfIfaceID).To(Equal("iface-id"))
			Expect(port.brName).To(Equal("br-test"))
		})

		It("returns error if ifaceID is empty", func() {
			patches.ApplyFunc(getIfaceID, func(string) (string, error) {
				return "", nil // 模拟返回空字符串
			})
			port, err := getPortInfo("eth0")
			Expect(port).To(BeNil())
			Expect(err).To(MatchError(ContainSubstring("can't find interface")))
		})

		It("returns error if port mounts to empty bridge", func() {
			patches.ApplyFunc(excuteCommand, func(cmd string) (string, error) {
				if strings.Contains(cmd, "port-to-br") {
					return "", nil // 模拟桥名为空
				}
				return fakeCmdOutput, nil
			})
			port, err := getPortInfo("eth0")
			Expect(port).To(BeNil())
			Expect(err).To(MatchError(ContainSubstring("mount to empty bridge")))
		})
	})

	Describe("Port Methods", func() {
		var p *Port

		BeforeEach(func() {
			p = &Port{
				uuid:            "uuid-123",
				name:            "eth0",
				brName:          svcChainBr,
				intfIfaceID:     "iface-id-1",
				intfExternalIDs: "some-external-id",
			}
		})

		Describe("checkTRNicInSvcChain", func() {
			It("returns true if ifaceID matches and bridge is svcchain", func() {
				Expect(p.checkTRNicInSvcChain("iface-id-1")).To(BeTrue())
			})

			It("returns false if bridge does not match svcchain", func() {
				p.brName = "br-other"
				Expect(p.checkTRNicInSvcChain("iface-id-1")).To(BeFalse())
			})

			It("returns false if ifaceID does not match", func() {
				Expect(p.checkTRNicInSvcChain("wrong-id")).To(BeFalse())
			})
		})

		Describe("checkTRNicHasMount", func() {
			BeforeEach(func() {
				p.brName = "br-test-policy"
			})
			It("returns true if bridge and ifaceID match", func() {
				Expect(p.checkTRNicHasMount("iface-id-1", "br-test")).To(BeTrue())
			})

			It("returns false if bridge does not match", func() {
				p.brName = "br-different"
				Expect(p.checkTRNicHasMount("iface-id-1", "br-test")).To(BeFalse())
			})

			It("returns false if ifaceID does not match", func() {
				Expect(p.checkTRNicHasMount("wrong-id", "br-test")).To(BeFalse())
			})
		})

		Describe("toNicCfg", func() {
			It("creates TRNicCfg with internal uuid if portUUID not given", func() {
				cfg := p.toNicCfg()
				Expect(cfg.PortUUID).To(Equal("uuid-123"))
				Expect(cfg.IfaceID).To(Equal("iface-id-1"))
				Expect(cfg.PortName).To(Equal("eth0"))
			})

			It("overrides uuid if portUUID is passed", func() {
				cfg := p.toNicCfg("override-uuid")
				Expect(cfg.PortUUID).To(Equal("override-uuid"))
			})
			It("sets empty PortUUID if both internal and argument are empty", func() {
				p.uuid = "" // clear internal uuid
				cfg := p.toNicCfg()
				Expect(cfg.PortUUID).To(BeEmpty())
				Expect(cfg.IfaceID).To(Equal("iface-id-1"))
				Expect(cfg.PortName).To(Equal("eth0"))
			})
		})
	})

	Describe("getIfaceID", func() {
		BeforeEach(func() {
			cmd := fmt.Sprintf("ovs-vsctl add-br %s -- add-port %s %s -- set interface %s external_ids='%s'", testBr1, testBr1, tap1, tap1, externalIDs1)
			_, err := excuteCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
			cmd = fmt.Sprintf("ovs-vsctl -- add-port %s %s -- set interface %s external_ids='%s'", testBr1, tap2, tap2, externalIDs2)
			_, err = excuteCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
		})
		AfterEach(func() {
			cmd := fmt.Sprintf("ovs-vsctl del-br %s", testBr1)
			_, err := excuteCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
		})

		It("return empty when interface has no ifaceID externalids", func() {
			res, err := getIfaceID(tap2)
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(res).Should(Equal(""))
		})

		It("return empty when interface is not exist", func() {
			res, err := getIfaceID(tap0)
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(res).Should(Equal(""))
		})

		It("return ifaceID", func() {
			res, err := getIfaceID(tap1)
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(res).Should(Equal(ifaceID1))
		})
	})

	Describe("getInterfaceExternalIDs", func() {
		BeforeEach(func() {
			cmd := fmt.Sprintf("ovs-vsctl add-br %s -- add-port %s %s -- set interface %s external_ids='%s'", testBr1, testBr1, tap1, tap1, externalIDs1)
			_, err := excuteCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
			cmd = fmt.Sprintf("ovs-vsctl -- add-port %s %s", testBr1, tap2)
			_, err = excuteCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
		})
		AfterEach(func() {
			cmd := fmt.Sprintf("ovs-vsctl del-br %s", testBr1)
			_, err := excuteCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
		})

		It("return err when interface is not exists", func() {
			res, err := getInterfaceExternalIDs(tap0)
			g.Expect(err).Should(HaveOccurred())
			g.Expect(res).Should(Equal(""))
		})

		It("return empty when interface has no externalids", func() {
			res, err := getInterfaceExternalIDs(tap2)
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(res).Should(Equal("{}"))
		})

		It("success get externalids", func() {
			res, err := getInterfaceExternalIDs(tap1)
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(res).Should(Equal(externalIDs1))
		})
	})

	Describe("findTrafficRedirectNic", func() {
		BeforeEach(func() {
			cmd := fmt.Sprintf("ovs-vsctl add-br %s -- add-port %s %s -- set interface %s external_ids='%s'", testBr1, testBr1, tap1, tap1, externalIDs1)
			_, err := excuteCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
			cmd = fmt.Sprintf("ovs-vsctl -- add-port %s %s -- set interface %s external_ids='%s'", testBr1, tap2, tap2, externalIDs0)
			_, err = excuteCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
			cmd = fmt.Sprintf("ovs-vsctl -- add-port %s %s -- set interface %s external_ids='%s'", testBr1, tap0, tap0, externalIDs0)
			_, err = excuteCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
		})
		AfterEach(func() {
			cmd := fmt.Sprintf("ovs-vsctl del-br %s", testBr1)
			_, err := excuteCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
		})

		It("should find the correct nic with valid ifaceID", func() {
			nic, err := findTrafficRedirectNic(testBr1, ifaceID1, types.NicIn)
			g.Expect(err).ShouldNot(HaveOccurred())
			g.Expect(nic).To(Equal(tap1))
		})

		It("should return error when ifaceID not found", func() {
			_, err := findTrafficRedirectNic(testBr1, "not-exist-id", types.NicIn)
			g.Expect(err).Should(HaveOccurred())
			g.Expect(err.Error()).To(ContainSubstring("can't find trafficredirect nic"))
		})

		It("should return error when multiple interfaces found", func() {
			_, err := findTrafficRedirectNic(testBr1, ifaceID0, types.NicIn)
			g.Expect(err).Should(HaveOccurred())
			g.Expect(err.Error()).To(ContainSubstring("find multi nic match trafficredirect"))
		})

		It("should return error when output format is invalid", func() {
			p := gomonkey.ApplyFuncReturn(excuteCommand, "iface-id:test:9", nil)
			defer p.Reset()

			_, err := findTrafficRedirectNic(testBr1, ifaceID1, types.NicOut)
			g.Expect(err).Should(HaveOccurred())
			g.Expect(err.Error()).To(ContainSubstring("invalid ovs out"))
		})
	})

	Describe("MountTRNic", func() {
		BeforeEach(func() {
			cmd := fmt.Sprintf("ovs-vsctl add-br %s -- add-port %s %s -- set interface %s external_ids='%s'", svcChainBr, svcChainBr, tap0, tap0, externalIDs0)
			_, err := excuteCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
			cmd = fmt.Sprintf("ovs-vsctl add-br %s-policy", testBr1)
			_, err = excuteCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
		})
		AfterEach(func() {
			cmd := fmt.Sprintf("ovs-vsctl del-br %s-policy", testBr1)
			_, err := excuteCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
			cmd = fmt.Sprintf("ovs-vsctl del-br %s", svcChainBr)
			_, err = excuteCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
		})

		It("success mount", func() {
			err := MountTRNic(testBr1, tap0, ifaceID0, types.NicIn)
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
			g.Expect(c.PortUUID).ShouldNot(Equal(""))
		})

		When("nic rebuild", func() {
			BeforeEach(func() {
				err := MountTRNic(testBr1, tap0, ifaceID0, types.NicIn)
				g.Expect(err).ShouldNot(HaveOccurred())
				t, err := getNicConfig(testBr1, types.NicIn)
				g.Expect(err).ShouldNot(HaveOccurred())
				g.Expect(t).ShouldNot(BeNil())
				t.PortUUID = "test"
				err = updateNicConfig(testBr1, types.NicIn, t)
				g.Expect(err).ShouldNot(HaveOccurred())
			})
			It("update port uuid to cfg", func() {
				err := MountTRNic(testBr1, tap0, ifaceID0, types.NicIn)
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
				g.Expect(c.PortUUID).ShouldNot(Equal("test"))
			})
		})

	})

	Describe("UnmountTRNic", func() {
		AfterEach(func() {
			cmd := fmt.Sprintf("ovs-vsctl --if-exists del-br %s-policy", testBr1)
			_, err := excuteCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
			cmd = fmt.Sprintf("ovs-vsctl del-br %s", svcChainBr)
			_, err = excuteCommand(cmd)
			g.Expect(err).ShouldNot(HaveOccurred())
		})

		When("iface doesn't exists", func() {
			BeforeEach(func() {
				cmd := fmt.Sprintf("ovs-vsctl add-br %s", svcChainBr)
				_, err := excuteCommand(cmd)
				g.Expect(err).ShouldNot(HaveOccurred())
				c := TRNicCfg{
					IfaceID:  ifaceID0,
					PortName: tap0,
				}
				err = updateNicConfig(testBr1, types.NicOut, &c)
				g.Expect(err).ShouldNot(HaveOccurred())
			})

			It("success clear config", func() {
				err := UnmountTRNic(testBr1, types.NicOut)
				g.Expect(err).ShouldNot(HaveOccurred())
				c, err := getNicConfig(testBr1, types.NicOut)
				g.Expect(err).ShouldNot(HaveOccurred())
				g.Expect(c).Should(BeNil())
			})
		})

		When("unmount nic", func() {
			BeforeEach(func() {
				cmd := fmt.Sprintf("ovs-vsctl add-br %s -- add-port %s %s -- set interface %s external_ids='%s'", svcChainBr, svcChainBr, tap0, tap0, externalIDs0)
				_, err := excuteCommand(cmd)
				g.Expect(err).ShouldNot(HaveOccurred())
				cmd = fmt.Sprintf("ovs-vsctl add-br %s-policy", testBr1)
				_, err = excuteCommand(cmd)
				g.Expect(err).ShouldNot(HaveOccurred())
				err = MountTRNic(testBr1, tap0, ifaceID0, types.NicOut)
				g.Expect(err).ShouldNot(HaveOccurred())
				p, err := getPortInfo(tap0)
				g.Expect(err).ShouldNot(HaveOccurred())
				g.Expect(p).ShouldNot(BeNil())
				g.Expect(p.brName).Should(Equal(testBr1 + "-policy"))
			})
			It("success unmount", func() {
				err := UnmountTRNic(testBr1, types.NicOut)
				g.Expect(err).ShouldNot(HaveOccurred())
				c, err := getNicConfig(testBr1, types.NicOut)
				g.Expect(err).ShouldNot(HaveOccurred())
				g.Expect(c).Should(BeNil())

				p, err := getPortInfo(tap0)
				g.Expect(err).ShouldNot(HaveOccurred())
				g.Expect(p).ShouldNot(BeNil())
				g.Expect(p.brName).Should(Equal(svcChainBr))
				g.Expect(p.intfExternalIDs).Should(Equal(externalIDs0))
				g.Expect(p.intfIfaceID).Should(Equal(ifaceID0))
			})
		})

	})
})
