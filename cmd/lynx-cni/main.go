package main

import (
	"github.com/containernetworking/cni/pkg/skel"
	cniversion "github.com/containernetworking/cni/pkg/version"

	"github.com/smartxworks/lynx/pkg/cni"
)

func main() {
	skel.PluginMain(
		cni.AddRequest,
		cni.CheckRequest,
		cni.DelRequest,
		cniversion.All,
		"Lynx CNI Client",
	)
}
