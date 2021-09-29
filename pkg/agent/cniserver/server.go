/*
Copyright 2021 The Everoute Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cniserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/containernetworking/cni/pkg/types"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/allocator"
	"github.com/contiv/ofnet/ovsdbDriver"
	"github.com/j-keck/arping"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"
	coretypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/everoute/everoute/pkg/agent/datapath"
	cnipb "github.com/everoute/everoute/pkg/apis/cni/v1alpha1"
	"github.com/everoute/everoute/pkg/utils"
)

const CNISocketAddr = "/var/run/everoute/cni.sock"

type CNIServer struct {
	k8sClient client.Client
	ovsDriver *ovsdbDriver.OvsDriver
	gwName    string
	brName    string
	podCIDR   []types.IPNet

	mutex sync.Mutex
}

type CNIArgs struct {
	types.CommonArgs
	K8S_POD_NAME               types.UnmarshallableString //nolint
	K8S_POD_NAMESPACE          types.UnmarshallableString //nolint
	K8S_POD_INFRA_CONTAINER_ID types.UnmarshallableString //nolint
}

func (s *CNIServer) ParseConf(request *cnipb.CniRequest) (*types.NetConf, *CNIArgs, error) {
	// parse request Stdin
	conf := &types.NetConf{}
	err := json.Unmarshal(request.Stdin, &conf)
	if err != nil {
		return nil, nil, err
	}

	// parse request Args
	args := &CNIArgs{}
	err = types.LoadArgs(request.Args, args)
	if err != nil {
		return nil, nil, err
	}

	return conf, args, err
}

func (s *CNIServer) ParseResult(result *cniv1.Result) (*cnipb.CniResponse, error) {
	// convert result to target version
	newResult, err := result.GetAsVersion(result.CNIVersion)
	if err != nil {
		klog.Errorf("get target version error, err: %s", err)
		return s.RetError(cnipb.ErrorCode_INCOMPATIBLE_CNI_VERSION, "get target version error", err)
	}

	var resultBytes bytes.Buffer
	if err = newResult.PrintTo(&resultBytes); err != nil {
		klog.Errorf("can not convert result automatically, err: %s", err)
		return s.RetError(cnipb.ErrorCode_INCOMPATIBLE_CNI_VERSION, "can not convert result automatically", err)
	}

	return &cnipb.CniResponse{
		Result: resultBytes.Bytes(),
		Error:  nil,
	}, nil
}

func (s *CNIServer) CmdAdd(ctx context.Context, request *cnipb.CniRequest) (*cnipb.CniResponse, error) {
	klog.Infof("Create new pod %s", request)

	s.mutex.Lock()
	defer s.mutex.Unlock()

	conf, args, err := s.ParseConf(request)
	if err != nil {
		klog.Errorf("Parse request conf error, err: %s", err)
		return s.RetError(cnipb.ErrorCode_DECODING_FAILURE, "Parse request conf error", err)
	}

	// require ipam for a new ip address
	SetEnv(request)
	r, err := ipam.ExecAdd("host-local", s.GetIpamConfByte(conf))
	if err != nil {
		klog.Errorf("could not allocate ip address, err: %s", err)
		return s.RetError(cnipb.ErrorCode_INVALID_NETWORK_CONFIG, "could not allocate ip address", err)
	}
	ipamResult, err := cniv1.NewResultFromResult(r)
	if err != nil {
		klog.Errorf("could not convert result, err: %s", err)
		return s.RetError(cnipb.ErrorCode_DECODING_FAILURE, "could not convert result", err)
	}

	// create cni result structure
	result := &cniv1.Result{
		CNIVersion: conf.CNIVersion,
		IPs:        ipamResult.IPs,
		Routes: []*types.Route{{
			Dst: net.IPNet{
				IP:   net.IPv4zero,
				Mask: net.IPMask(net.IPv4zero)},
			GW: ipamResult.IPs[0].Gateway}},
		Interfaces: []*cniv1.Interface{{
			Name:    request.Ifname,
			Sandbox: request.Netns}},
	}
	// set the correspondence between interface and ip address
	result.IPs[0].Interface = cniv1.Int(0)

	nsPath := "/host" + request.Netns
	// vethName - ovs port name
	vethName := request.ContainerId[:12]
	if err = ns.WithNetNSPath(nsPath, func(hostNS ns.NetNS) error {
		// create veth pair in container NS and host NS
		// TODO: MTU is a const variable here
		_, containerVeth, err := ip.SetupVethWithName(request.Ifname, vethName, 1500, "", hostNS)
		if err != nil {
			klog.Errorf("create veth device error, err: %s", err)
			return err
		}
		result.Interfaces[0].Mac = containerVeth.HardwareAddr.String()
		if err = ipam.ConfigureIface(request.Ifname, result); err != nil {
			klog.Errorf("configure ip address in container error, err: %s", err)
			return err
		}
		return nil
	}); err != nil {
		return s.RetError(cnipb.ErrorCode_IO_FAILURE, "exec error in namespace", err)
	}

	// add the veth device to ovs bridge
	err = s.ovsDriver.CreatePort(vethName, "", 0)
	if err != nil {
		klog.Errorf("create ovs port error, vethName: %s, err: %s", vethName, err)
		return s.RetError(cnipb.ErrorCode_IO_FAILURE, "add port to ovs bridge error", err)
	}

	// set externalID on the interface for arp learning
	externalID := make(map[string]string)
	externalID["attached-mac"] = result.Interfaces[0].Mac
	externalID["pod-uuid"] = utils.EncodeNamespacedName(coretypes.NamespacedName{
		Name:      "pod-" + string(args.K8S_POD_NAME),
		Namespace: string(args.K8S_POD_NAMESPACE),
	})
	err = s.ovsDriver.UpdateInterface(vethName, externalID)
	if err != nil {
		klog.Errorf("set externalID for %s error, err: %s", vethName, err)
		return s.RetError(cnipb.ErrorCode_IO_FAILURE, "set externalID for %s error", err)
	}

	// broadcast arp pkg in namespace
	// pod-endpoint may not sync when sending arp, so this part may not have effects.
	if err = ns.WithNetNSPath(nsPath, func(hostNS ns.NetNS) error {
		for index := range result.IPs {
			err = arping.GratuitousArpOverIfaceByName(result.IPs[index].Address.IP,
				result.Interfaces[*result.IPs[index].Interface].Name)
			if err != nil {
				klog.Errorf("get error while arping, err: %s\n", err)
				return err
			}
		}
		return nil
	}); err != nil {
		klog.Errorf("exec in namespace error, err: %s", err)
	}

	return s.ParseResult(result)
}

func (s *CNIServer) CmdCheck(ctx context.Context, request *cnipb.CniRequest) (*cnipb.CniResponse, error) {
	klog.Infof("Check pod %s", request)

	s.mutex.Lock()
	defer s.mutex.Unlock()

	conf, _, err := s.ParseConf(request)
	if err != nil {
		klog.Errorf("failed to decode request, err: %s", err)
		return s.RetError(cnipb.ErrorCode_DECODING_FAILURE, "failed to decode request", err)
	}

	vethName := request.ContainerId[:12]

	// check ovs port
	if !s.ovsDriver.IsPortNamePresent(vethName) {
		klog.Errorf("ovs port does not exist, err: %s", err)
		return s.RetError(cnipb.ErrorCode_IO_FAILURE, "ovs port does not exist", err)
	}

	// require ipam for a new ip address
	SetEnv(request)
	err = ipam.ExecCheck("host-local", s.GetIpamConfByte(conf))
	if err != nil {
		klog.Errorf("ipam check error, err: %s", err)
		return s.RetError(cnipb.ErrorCode_IO_FAILURE, "ipam check error", err)
	}

	return &cnipb.CniResponse{Result: []byte("")}, nil
}

func (s *CNIServer) CmdDel(ctx context.Context, request *cnipb.CniRequest) (*cnipb.CniResponse, error) {
	klog.Infof("Delete pod %s", request)

	s.mutex.Lock()
	defer s.mutex.Unlock()

	conf, _, err := s.ParseConf(request)
	if err != nil {
		klog.Errorf("Parse request conf error, err: %s", err)
		return s.RetError(cnipb.ErrorCode_DECODING_FAILURE, "Parse request conf error", err)
	}

	vethName := request.ContainerId[:12]

	// delete ovs port
	if s.ovsDriver.IsPortNamePresent(vethName) {
		if err = s.ovsDriver.DeletePort(vethName); err != nil {
			klog.Errorf("delete ovs port %s error, err: %s", vethName, err)
			return s.RetError(cnipb.ErrorCode_IO_FAILURE, "delete ovs port error", err)
		}
	}

	// release allocated IP
	SetEnv(request)
	if err = ipam.ExecDel("host-local", s.GetIpamConfByte(conf)); err != nil {
		klog.Errorf("release ip error, ipam conf: %s, err: %s", conf.IPAM, err)
		return s.RetError(cnipb.ErrorCode_IO_FAILURE, "release ip error", err)
	}

	return s.ParseResult(&cniv1.Result{CNIVersion: conf.CNIVersion})
}

func (s *CNIServer) RetError(code cnipb.ErrorCode, msg string, err error) (*cnipb.CniResponse, error) {
	resp := &cnipb.CniResponse{
		Result: nil,
		Error: &cnipb.Error{
			Code:    code,
			Message: msg,
			Details: err.Error(),
		},
	}
	return resp, err
}

func (s *CNIServer) GetIpamConfByte(conf *types.NetConf) []byte {
	var ipamRanges allocator.RangeSet
	for _, item := range s.podCIDR {
		ipamRanges = append(ipamRanges, allocator.Range{Subnet: item})
	}

	ipamConf := allocator.Net{
		Name:       conf.Name,
		CNIVersion: conf.CNIVersion,
		IPAM: &allocator.IPAMConfig{
			Type:   "host-local",
			Ranges: []allocator.RangeSet{ipamRanges},
		},
		Args: nil,
	}
	ipamByte, _ := json.Marshal(ipamConf)

	return ipamByte
}

func SetEnv(request *cnipb.CniRequest) {
	os.Setenv("CNI_PATH", request.Path)
	os.Setenv("CNI_CONTAINERID", request.ContainerId)
	os.Setenv("CNI_NETNS", request.Netns)
	os.Setenv("CNI_IFNAME", request.Ifname)
}

func SetLinkAddr(ifname string, inet *net.IPNet) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		klog.Errorf("failed to lookup %q: %v", ifname, err)
		return err
	}
	if err = netlink.LinkSetUp(link); err != nil {
		klog.Errorf("failed to set %q UP: %v", ifname, err)
		return err
	}
	addr := &netlink.Addr{
		IPNet: inet,
		Label: ""}
	if err = netlink.AddrAdd(link, addr); err != nil {
		klog.Errorf("failed to add IP addr to %s: %v", ifname, err)
		return err
	}
	return nil
}

func Initialize(k8sClient client.Client, dpManager *datapath.DpManager) *CNIServer {
	s := &CNIServer{
		k8sClient: k8sClient,
	}

	klog.Infof("%+v", dpManager.OvsdbDriverMap)
	for name := range dpManager.OvsdbDriverMap {
		s.brName = name
		s.gwName = name + "-gw"
		s.ovsDriver = dpManager.OvsdbDriverMap[name][datapath.LOCAL_BRIDGE_KEYWORD]
		break
	}

	// get current node
	// TODO: hostname cannot be modified after joining into cluster
	nodeName, _ := os.Hostname()
	nodeName = strings.ToLower(nodeName)
	node := corev1.Node{}
	if err := s.k8sClient.Get(context.Background(), client.ObjectKey{
		Name: nodeName,
	}, &node); err != nil {
		klog.Fatalf("get node info error, err:%s", err)
	}

	// record all pod CIDRs
	for _, cidrString := range node.Spec.PodCIDRs {
		cidr, _ := types.ParseCIDR(cidrString)
		s.podCIDR = append(s.podCIDR, types.IPNet(*cidr))
	}

	// set gateway ip address, first ip in first CIDR
	if err := SetLinkAddr(s.gwName,
		&net.IPNet{
			IP:   ip.NextIP(s.podCIDR[0].IP),
			Mask: s.podCIDR[0].Mask}); err != nil {
		klog.Errorf("set gateway ip address error, err:%s", err)
	}

	return s
}

func (s *CNIServer) Run(stopChan <-chan struct{}) {
	klog.Info("Starting CNI server")

	// remove the remaining sock file
	_, err := os.Stat(CNISocketAddr)
	if err == nil {
		err = os.Remove(CNISocketAddr)
		if err != nil {
			klog.Fatalf("remove remaining cni sock file error, err:%s", err)
			return
		}
	}

	// listen and start rpcServer
	listener, err := net.Listen("unix", CNISocketAddr)
	if err != nil {
		klog.Fatalf("Failed to bind on %s: %v", CNISocketAddr, err)
	}
	rpcServer := grpc.NewServer()
	cnipb.RegisterCniServer(rpcServer, s)
	go func() {
		if err = rpcServer.Serve(listener); err != nil {
			klog.Fatalf("Failed to serve connections: %v", err)
		}
	}()

	klog.Info("CNI server is listening ...")
	<-stopChan
}
