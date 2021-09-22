package main

import (
	"github.com/containernetworking/cni/pkg/skel"
	cniversion "github.com/containernetworking/cni/pkg/version"

	"github.com/everoute/everoute/pkg/cni"
)

func main() {
	skel.PluginMain(
		cni.AddRequest,
		cni.CheckRequest,
		cni.DelRequest,
		cniversion.All,
		"Everoute CNI Client",
	)
}
