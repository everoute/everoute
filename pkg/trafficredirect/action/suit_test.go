package action

import (
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/everoute/everoute/pkg/constants/tr"
)

const (
	svcChainBr = "test-svcchain"
	testBr1    = "test-br1"
	testBr2    = "test-br2"

	tap0 = "test-tap0"
	tap1 = "test-tap1"
	tap2 = "test-tap2"

	ifaceID0 = "aadd4891-c698-4a07-8fc8-1bbbcfea05d5"
	ifaceID1 = "1ef4eb24-1418-4355-9ab4-399d86be09ba"

	externalIDs0 = "{attached-mac=\"52:54:00:d9:76:ac\", iface-id=\"aadd4891-c698-4a07-8fc8-1bbbcfea05d5\", iface-status=active}"
	externalIDs1 = "{attached-mac=\"52:54:00:d8:76:ac\", iface-id=\"1ef4eb24-1418-4355-9ab4-399d86be09ba\", iface-status=active}"
	externalIDs2 = "{attached-mac=\"52:54:00:d7:76:ac\", iface-status=active}"
)

var (
	svcChainP *gomonkey.Patches
	g         = NewWithT(GinkgoT())
)

var _ = BeforeSuite(func() {
	svcChainP = gomonkey.ApplyGlobalVar(&tr.SvcChainBridgeName, svcChainBr)
	tapCmd := `
	ip tuntap add dev test-tap0 mode tap
	ip tuntap add dev test-tap1 mode tap
	ip tuntap add dev test-tap2 mode tap
	`
	_, err := executeCommand(tapCmd)
	Expect(err).ShouldNot(HaveOccurred())
})

var _ = AfterSuite(func() {
	svcChainP.Reset()

	tapCmd := `
	ip link del test-tap0
	ip link del test-tap1
	ip link del test-tap2
	`
	_, err := executeCommand(tapCmd)
	Expect(err).ShouldNot(HaveOccurred())
})

func TestAction(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "trafficredirect action")
}
