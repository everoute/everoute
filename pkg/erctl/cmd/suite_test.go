package cmd

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestCmds(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Cmds Suite")
}
