package version

import (
	"fmt"
	"runtime"
	"strconv"

	goversion "github.com/hashicorp/go-version"
	"k8s.io/apimachinery/pkg/version"
)

// version and commit are injected at build time
var (
	releaseVersion = "0.0.0-dev"
	releaseCommit  = "DEV"
)

func GetHumanVersion() string {
	return fmt.Sprintf("%s (%s)", releaseVersion, releaseCommit)
}

func GetVersionInfo() *version.Info {
	var (
		versionMajor = "1"
		versionMinor = "0"
	)

	v, err := goversion.NewVersion(releaseVersion)
	if err == nil {
		if len(v.Segments()) >= 1 {
			versionMajor = strconv.Itoa(v.Segments()[0])
		}
		if len(v.Segments()) >= 2 {
			versionMinor = strconv.Itoa(v.Segments()[1])
		}
	}
	return &version.Info{
		Major:        versionMajor,
		Minor:        versionMinor,
		GitVersion:   releaseVersion,
		GitCommit:    releaseCommit,
		GitTreeState: "clean",
		GoVersion:    runtime.Version(),
		Compiler:     runtime.Compiler,
		Platform:     fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}
