package erctl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/everoute/everoute/pkg/apis/rpc/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
)

var (
	bridgeNameSuffix = []string{"", "-policy", "-cls", "-uplink"}
	allBridge        []string
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
	flowconn := v1alpha1.NewCollectorClient(rpc)
	vdsName, err := flowconn.GetChainBridge(context.Background(), &emptypb.Empty{})
	if err != nil {
		return err
	}
	allBridge = vdsName2BridgeName(vdsName.Bridge...)
	return nil
}

func GetFlows(dp bool, names ...string) (map[string][]string, error) {
	if !dp && len(names) == 0 {
		names = allBridge
		dp = true
	} else if len(names) != 0 {
		ans := []string{}
		added := make([]bool, len(allBridge))
		for _, name := range names {
			want, err := regexp.Compile(name)
			if err != nil {
				return nil, err
			}
			for i := 0; i < len(allBridge) && !added[i]; i++ {
				bridge := allBridge[i]
				if want.FindString(bridge) == bridge {
					ans = append(ans, bridge)
					added[i] = true
				}
			}
		}
		names = ans
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

// vdsName means localBridgeName
func vdsName2BridgeName(vdsName ...string) []string {
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
