package cni

import (
	"context"
	"net"
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	cnipb "github.com/everoute/everoute/pkg/apis/rpc/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
)

func rpcRequest(requestType string, arg *skel.CmdArgs) error {
	conn, err := grpc.Dial(constants.RPCSocketAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
			unixAddr, _ := net.ResolveUnixAddr("unix", constants.RPCSocketAddr)
			connUnix, err := net.DialUnix("unix", nil, unixAddr)
			return connUnix, err
		}))
	if err != nil {
		return err
	}
	defer conn.Close()

	client := cnipb.NewCniClient(conn)

	cmdRequest := cnipb.CniRequest{
		ContainerId: arg.ContainerID,
		Ifname:      arg.IfName,
		Args:        arg.Args,
		Netns:       arg.Netns,
		Stdin:       arg.StdinData,
		Path:        arg.Path,
	}

	var resp *cnipb.CniResponse

	switch requestType {
	case "add":
		resp, err = client.CmdAdd(context.Background(), &cmdRequest)
	case "del":
		resp, err = client.CmdDel(context.Background(), &cmdRequest)
	case "check":
		resp, err = client.CmdCheck(context.Background(), &cmdRequest)
	}

	// rpc errors
	switch status.Code(err) {
	case codes.Unimplemented:
		return &types.Error{
			Code:    uint(cnipb.ErrorCode_UNKNOWN),
			Msg:     "incompatible CNI API version between controller and agent",
			Details: err.Error(),
		}
	case codes.Unavailable, codes.DeadlineExceeded:
		return &types.Error{
			Code: uint(cnipb.ErrorCode_TRY_AGAIN_LATER),
			Msg:  err.Error(),
		}
	case codes.Unknown:
		return &types.Error{
			Code: uint(cnipb.ErrorCode_UNKNOWN),
			Msg:  err.Error(),
		}
	}

	if resp.Error != nil {
		return &types.Error{
			Code:    uint(resp.Error.Code),
			Msg:     resp.Error.Message,
			Details: resp.Error.Details,
		}
	}

	os.Stdout.Write(resp.Result)

	return nil
}

func AddRequest(arg *skel.CmdArgs) error {
	return rpcRequest("add", arg)
}

func DelRequest(arg *skel.CmdArgs) error {
	return rpcRequest("del", arg)
}

func CheckRequest(arg *skel.CmdArgs) error {
	return rpcRequest("check", arg)
}
