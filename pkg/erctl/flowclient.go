package erctl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	flowpb "github.com/everoute/everoute/pkg/apis/rpc/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"net"
	"os/exec"
	"strings"
)

var (
	flowconn         flowpb.CollectorClient
	bridgeNameSuffix = []string{"", "-policy", "-cls", "-uplink"}
)

func ConnectFlow() error {
	rpc, err := grpc.Dial(constants.RPCSocketAddr,
		grpc.WithInsecure(),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (conn net.Conn, e error) {
			unixAddr, _ := net.ResolveUnixAddr("unix", constants.RPCSocketAddr)
			connUnix, err := net.DialUnix("unix", nil, unixAddr)
			return connUnix, err
		}))
	if err != nil {
		return err
	}
	flowconn = flowpb.NewCollectorClient(rpc)
	return nil
}

func GetFlows(dp bool, names ...string) (map[string][]string, error) {
	if dp != true && len(names) == 0 {
		vdsName, err := flowconn.GetChainBridge(context.Background(), &emptypb.Empty{})
		if err != nil {
			return nil, err
		}
		names = VdsName2BridgeName(vdsName.Bridge...)
		dp = true
	}
	laste := errors.New("cmd has err")
	ans := map[string][]string{}
	for _, name := range names {
		cmd := fmt.Sprintf("ovs-ofctl dump-flows %s", name)
		b, err := exec.Command("/bin/sh", "-c", cmd).CombinedOutput()
		if err != nil {
			laste = fmt.Errorf("%s,%s", laste.Error(), err.Error())
			continue
		}
		flows := strings.Split(string(bytes.TrimSpace(b)), "\n")
		ans[name] = flows
	}
	if dp {
		b, err := exec.Command("/bin/sh", "-c", "ovs-dpctl dump-flows").CombinedOutput()
		if err != nil {
			laste = fmt.Errorf("%s,%s", laste.Error(), err.Error())

		} else {
			dpthing := strings.Split(string(bytes.TrimSpace(b)), "\n")
			ans["dp"] = dpthing
		}
	}
	if laste.Error() == "cmd has err" {
		laste = nil
	}
	return ans, laste
}

func VdsName2BridgeName(vdsName ...string) []string {
	bridge := make([]string, len(vdsName)*4)
	i := 0
	for _, s := range vdsName {
		for _, s2 := range bridgeNameSuffix {
			bridge[i] = s + s2
			i++
		}
	}
	return bridge
}
