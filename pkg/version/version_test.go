package version

import (
	"fmt"
	"runtime"
	"testing"

	. "github.com/onsi/gomega"
)

func TestGetHumanVersion(t *testing.T) {
	RegisterTestingT(t)

	releaseVersion = "2.0.0"
	releaseCommit = "7663da7"
	Expect(GetHumanVersion()).Should(Equal("2.0.0 (7663da7)"))
}

func TestGetVersionInfo(t *testing.T) {
	RegisterTestingT(t)

	releaseVersion = "2.0.0"
	releaseCommit = "7663da7"

	v := GetVersionInfo()
	Expect(v.Major).Should(Equal("2"))
	Expect(v.Minor).Should(Equal("0"))
	Expect(v.GitVersion).Should(Equal(releaseVersion))
	Expect(v.GitCommit).Should(Equal(releaseCommit))
	Expect(v.GitTreeState).Should(Equal("clean"))
	Expect(v.GoVersion).Should(Equal(runtime.Version()))
	Expect(v.Compiler).Should(Equal(runtime.Compiler))
	Expect(v.Platform).Should(Equal(fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)))
}
