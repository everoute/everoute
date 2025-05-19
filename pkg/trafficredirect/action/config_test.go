package action

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/agiledragon/gomonkey/v2"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"gopkg.in/yaml.v3"

	"github.com/everoute/everoute/pkg/types"
)

var _ = Describe("test config", func() {
	Describe("TRNicCfg", func() {
		var (
			cfg *TRNicCfg
		)

		BeforeEach(func() {
			cfg = &TRNicCfg{
				IfaceID:  "eth0",
				PortName: "port-eth0",
				PortUUID: "uuid-1234",
			}
		})

		Context("toBase64", func() {
			It("should encode and decode correctly", func() {
				encoded, err := cfg.toBase64()
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(encoded).NotTo(BeEmpty())

				decodedCfg, err := toTRNicCfg(encoded)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(decodedCfg).To(Equal(cfg))
			})
		})

		Context("toTRNicCfg error cases", func() {
			It("should return error for invalid base64", func() {
				_, err := toTRNicCfg("!!!invalid-base64!!!")
				g.Expect(err).To(HaveOccurred())
				g.Expect(errors.Is(err, base64.CorruptInputError(0))).To(BeTrue()) // just ensure it's an error
			})

			It("should return error for invalid yaml", func() {
				invalidYaml := base64.StdEncoding.EncodeToString([]byte("not: valid: yaml"))
				_, err := toTRNicCfg(invalidYaml)
				g.Expect(err).To(HaveOccurred())
			})
		})

		Context("corner cases", func() {
			It("should handle empty config", func() {
				emptyCfg := &TRNicCfg{}
				encoded, err := emptyCfg.toBase64()
				g.Expect(err).NotTo(HaveOccurred())

				decodedCfg, err := toTRNicCfg(encoded)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(decodedCfg).To(Equal(emptyCfg))
			})

			It("should handle PortUUID empty without portUUID field in yaml", func() {
				cfgWithEmptyUUID := &TRNicCfg{
					IfaceID:  "eth1",
					PortName: "port-eth1",
					PortUUID: "", // 重点：为空
				}
				// 先用 yaml.Marshal 出原始 yaml 内容
				yamlBytes, err := yaml.Marshal(cfgWithEmptyUUID)
				g.Expect(err).NotTo(HaveOccurred())
				yamlStr := string(yamlBytes)

				// 确保 yaml 中没有 portUUID 字段
				g.Expect(yamlStr).NotTo(ContainSubstring("portUUID"))

				// 再整体走一下 base64 流程
				encoded, err := cfgWithEmptyUUID.toBase64()
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(encoded).NotTo(BeEmpty())

				decodedCfg, err := toTRNicCfg(encoded)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(decodedCfg.IfaceID).To(Equal(cfgWithEmptyUUID.IfaceID))
				g.Expect(decodedCfg.PortName).To(Equal(cfgWithEmptyUUID.PortName))
				g.Expect(decodedCfg.PortUUID).To(Equal(""))
			})
		})
	})

	Describe("ExternalIDKey utils", func() {
		Context("getExternalIDKey", func() {
			It("should generate key with NicIn prefix", func() {
				key := getExternalIDKey("br-int", types.NicIn)
				g.Expect(key).To(Equal("tr-in-br-int"))
			})

			It("should generate key with NicOut prefix", func() {
				key := getExternalIDKey("br-ext", types.NicOut)
				g.Expect(key).To(Equal("tr-out-br-ext"))
			})
		})

		Context("parseExternalIDKey", func() {
			It("should parse NicIn key correctly", func() {
				found, bridgeName := parseExternalIDKey("tr-in-br-int")
				g.Expect(found).To(BeTrue())
				g.Expect(bridgeName).To(Equal("br-int"))
			})

			It("should parse NicOut key correctly", func() {
				found, bridgeName := parseExternalIDKey("tr-out-br-ext")
				g.Expect(found).To(BeTrue())
				g.Expect(bridgeName).To(Equal("br-ext"))
			})

			It("should return false for unknown prefix", func() {
				found, bridgeName := parseExternalIDKey("unknownPrefix-br")
				g.Expect(found).To(BeFalse())
				g.Expect(bridgeName).To(Equal(""))
			})

			It("should return false for no prefix", func() {
				found, bridgeName := parseExternalIDKey("br-int")
				g.Expect(found).To(BeFalse())
				g.Expect(bridgeName).To(Equal(""))
			})
		})
	})

	Describe("NicConfig utils", func() {

		Context("getNicConfig with mock", func() {
			It("should return valid TRNicCfg when executeCommand returns valid data", func() {
				patches := gomonkey.ApplyFunc(excuteCommand, func(cmd string) (string, error) {
					// 直接返回 Base64编码+YAML的mock数据
					yamlData := "ifaceID: eth0\nportName: port1\n"
					return base64.StdEncoding.EncodeToString([]byte(yamlData)), nil
				})
				defer patches.Reset()

				cfg, err := getNicConfig("br-int", types.NicIn)
				g.Expect(err).To(BeNil())
				g.Expect(cfg).NotTo(BeNil())
				g.Expect(cfg.IfaceID).To(Equal("eth0"))
				g.Expect(cfg.PortName).To(Equal("port1"))
			})

			It("should return nil when executeCommand returns empty output", func() {
				patches := gomonkey.ApplyFunc(excuteCommand, func(cmd string) (string, error) {
					return "", nil
				})
				defer patches.Reset()

				cfg, err := getNicConfig("br-int", types.NicIn)
				g.Expect(err).To(BeNil())
				g.Expect(cfg).To(BeNil())
			})

			It("should return error when executeCommand fails", func() {
				patches := gomonkey.ApplyFunc(excuteCommand, func(cmd string) (string, error) {
					return "", errors.New("mock error")
				})
				defer patches.Reset()

				cfg, err := getNicConfig("br-int", types.NicIn)
				g.Expect(err).NotTo(BeNil())
				g.Expect(cfg).To(BeNil())
			})
		})

		Context("delNicConfig with mock", func() {
			var patches *gomonkey.Patches

			AfterEach(func() {
				if patches != nil {
					patches.Reset()
				}
			})

			It("should fail if excuteCommand fails", func() {
				// 模拟 excuteCommand 函数返回错误
				patches = gomonkey.ApplyFunc(excuteCommand, func(cmd string) (string, error) {
					return "", errors.New("command failed")
				})

				err := delNicConfig("br-int", types.NicIn)

				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring("command failed"))
			})

			It("should succeed to delete external id", func() {
				// 模拟 excuteCommand 成功
				patches = gomonkey.ApplyFunc(excuteCommand, func(cmd string) (string, error) {
					return "ok", nil
				})

				err := delNicConfig("br-int", types.NicIn)

				g.Expect(err).To(BeNil())
			})
		})

		Context("updateNicConfig with mock", func() {
			var patches *gomonkey.Patches

			AfterEach(func() {
				if patches != nil {
					patches.Reset()
				}
			})

			It("should fail if input config is nil", func() {
				err := updateNicConfig("br-int", types.NicIn, nil)
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring("TRNicCfg is nil"))
			})

			It("should fail if toBase64 fails", func() {
				patches = gomonkey.NewPatches()
				patches = gomonkey.ApplyPrivateMethod(new(TRNicCfg), "toBase64", func() (string, error) {
					return "", errors.New("encode failed")
				})

				cfg := &TRNicCfg{IfaceID: "eth0"}
				err := updateNicConfig("br-int", types.NicIn, cfg)

				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring("encode failed"))
			})

			It("should fail if excuteCommand fails", func() {
				patches = gomonkey.NewPatches()
				patches = gomonkey.ApplyPrivateMethod(new(TRNicCfg), "toBase64", func() (string, error) {
					return "mocked-external-data", nil
				})
				patches.ApplyFunc(excuteCommand, func(cmd string) (string, error) {
					return "", errors.New("ovs command failed")
				})

				cfg := &TRNicCfg{IfaceID: "eth0"}
				err := updateNicConfig("br-int", types.NicIn, cfg)

				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring("ovs command failed"))
			})

			It("should succeed to update external id", func() {
				patches = gomonkey.NewPatches()
				patches = gomonkey.ApplyPrivateMethod(new(TRNicCfg), "toBase64", func() (string, error) {
					return "mocked-external-data", nil
				})
				patches.ApplyFunc(excuteCommand, func(cmd string) (string, error) {
					return "ok", nil
				})

				cfg := &TRNicCfg{IfaceID: "eth0"}
				err := updateNicConfig("br-int", types.NicIn, cfg)

				g.Expect(err).To(BeNil())
			})
		})

		Context("real execution without mock", func() {
			BeforeEach(func() {
				/*
					ifaceID: aadd4891-c698-4a07-8fc8-1bbbcfea05d5
					portUUID: 1ef4eb24-1418-4355-9ab4-399d86be09ba
					portName: test-tap0
				*/
				cmd := `
				ovs-vsctl add-br test-svcchain \
				-- br-set-external-id test-svcchain tr-out-test-br1 \
				aWZhY2VJRDogYWFkZDQ4OTEtYzY5OC00YTA3LThmYzgtMWJiYmNmZWEwNWQ1CnBvcnRVVUlEOiAxZWY0ZWIyNC0xNDE4LTQzNTUtOWFiNC0zOTlkODZiZTA5YmEKcG9ydE5hbWU6IHRlc3QtdGFwMAo=
				`
				_, err := excuteCommand(cmd)
				g.Expect(err).ShouldNot(HaveOccurred())
			})
			AfterEach(func() {
				cmd := `ovs-vsctl del-br test-svcchain`
				_, err := excuteCommand(cmd)
				g.Expect(err).ShouldNot(HaveOccurred())
			})
			Context("get nicConfig", func() {
				It("should return nil if ovs external-id is not set", func() {
					cfg, err := getNicConfig("br-not-set", types.NicIn)
					g.Expect(err).To(BeNil())
					g.Expect(cfg).To(BeNil())
				})
				It("should return real nicConfig", func() {
					cfg, err := getNicConfig(testBr1, types.NicOut)
					g.Expect(err).To(BeNil())
					g.Expect(cfg).ToNot(BeNil())
					g.Expect(cfg.IfaceID).Should(Equal(ifaceID0))
					g.Expect(cfg.PortUUID).Should(Equal("1ef4eb24-1418-4355-9ab4-399d86be09ba"))
					g.Expect(cfg.PortName).Should(Equal(tap0))
				})
			})
			Context("del nicConfig", func() {
				It("should success del empty nicConfig", func() {
					err := delNicConfig("br-not-set", types.NicOut)
					g.Expect(err).ShouldNot(HaveOccurred())
				})
				It("should success del nicConfig", func() {
					err := delNicConfig(testBr1, types.NicOut)
					g.Expect(err).ShouldNot(HaveOccurred())
					cfg, err := getNicConfig(testBr1, types.NicOut)
					g.Expect(err).To(BeNil())
					g.Expect(cfg).To(BeNil())
				})
			})
			Context("update nicConfig", func() {
				It("should set nicConfig", func() {
					trNicCfg := TRNicCfg{
						IfaceID:  "ifaceid",
						PortName: "portname",
						PortUUID: "",
					}
					err := updateNicConfig("bt-not-set", types.NicIn, &trNicCfg)
					g.Expect(err).ShouldNot(HaveOccurred())
					cfg, err := getNicConfig("bt-not-set", types.NicIn)
					g.Expect(err).To(BeNil())
					g.Expect(cfg).ToNot(BeNil())
					g.Expect(*cfg).Should(Equal(trNicCfg))
				})

				It("should update nicConfig", func() {
					trNicCfg := TRNicCfg{
						IfaceID:  "ifaceid",
						PortName: "portname",
						PortUUID: "",
					}
					err := updateNicConfig(testBr1, types.NicOut, &trNicCfg)
					g.Expect(err).ShouldNot(HaveOccurred())
					cfg, err := getNicConfig(testBr1, types.NicOut)
					g.Expect(err).To(BeNil())
					g.Expect(cfg).ToNot(BeNil())
					g.Expect(*cfg).Should(Equal(trNicCfg))
				})
			})
		})
	})

	Describe("getAllBridge", func() {
		var patches *gomonkey.Patches

		AfterEach(func() {
			if patches != nil {
				patches.Reset()
			}
		})

		Context("when excuteCommand returns error", func() {
			It("should return error", func() {
				patches = gomonkey.ApplyFunc(excuteCommand, func(cmd string) (string, error) {
					return "", fmt.Errorf("mock error")
				})

				bridges, err := getAllBridge()

				g := NewWithT(GinkgoT())
				g.Expect(err).To(HaveOccurred())
				g.Expect(bridges).To(BeNil())
			})
		})

		Context("when excuteCommand returns valid external ids", func() {
			It("should return a set of bridge names", func() {
				mockOutput := `

tr-in-br-int=abc
tr-out-br-ext=xyz
tr-out-br-int=hc
invalidline
foo=bar
tr-in-=emptykey
	`
				patches = gomonkey.ApplyFunc(excuteCommand, func(cmd string) (string, error) {
					return mockOutput, nil
				})

				bridges, err := getAllBridge()
				g := NewWithT(GinkgoT())
				g.Expect(err).To(BeNil())
				g.Expect(bridges.UnsortedList()).To(ConsistOf("br-ext", "br-int"))
				g.Expect(bridges.Len()).To(Equal(2)) // only br-int and br-ext
			})
		})

		Context("when excuteCommand returns empty output", func() {
			It("should return an empty set", func() {
				out := `
				
				`
				patches = gomonkey.ApplyFunc(excuteCommand, func(cmd string) (string, error) {
					return out, nil
				})

				bridges, err := getAllBridge()

				g := NewWithT(GinkgoT())
				g.Expect(err).To(BeNil())
				g.Expect(bridges.Len()).To(Equal(0))
			})
		})
	})
})
