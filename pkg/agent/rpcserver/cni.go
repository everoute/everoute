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

package rpcserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"sync"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/contiv/ofnet/ovsdbDriver"
	"github.com/j-keck/arping"
	"github.com/vishvananda/netlink"
	coretypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/everoute/everoute/pkg/agent/datapath"
	cnipb "github.com/everoute/everoute/pkg/apis/rpc/v1alpha1"
	"github.com/everoute/everoute/pkg/constants"
	eripam "github.com/everoute/everoute/pkg/ipam"
	"github.com/everoute/everoute/pkg/utils"
)

type CNIServer struct {
	k8sClient client.Client
	ovsDriver *ovsdbDriver.OvsDriver
	ipam      eripam.IPAM
	brName    string
	podMTU    int

	mutex sync.Mutex
}

func (s *CNIServer) ParseConf(request *cnipb.CniRequest) (*cnitypes.NetConf, *utils.CNIArgs, error) {
	// parse request Stdin
	conf := &cnitypes.NetConf{}
	err := json.Unmarshal(request.Stdin, &conf)
	if err != nil {
		return nil, nil, err
	}

	// parse request Args
	args := &utils.CNIArgs{}
	err = cnitypes.LoadArgs(request.Args, args)
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
	ipamResult, err := s.ipam.ExecAdd(ctx, conf, args)
	if err != nil {
		klog.Errorf("could not allocate ip address, err: %s", err)
		return s.RetError(cnipb.ErrorCode_INVALID_NETWORK_CONFIG, "could not allocate ip address", err)
	}

	// create cni result structure
	result := &cniv1.Result{
		CNIVersion: conf.CNIVersion,
		IPs:        ipamResult.IPs,
		Routes: []*cnitypes.Route{{
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
	vethName := "_" + request.ContainerId[:12]
	if err = ns.WithNetNSPath(nsPath, func(hostNS ns.NetNS) error {
		// create veth pair in container NS and host NS
		_, containerVeth, err := ip.SetupVethWithName(request.Ifname, vethName, s.podMTU, "", hostNS)
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
	if err = s.ovsDriver.CreatePort(vethName, "", 0); err != nil {
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
	externalID["attached-ipv4"] = result.IPs[0].Address.IP.String()
	if err = s.ovsDriver.UpdateInterface(vethName, externalID); err != nil {
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

	conf, args, err := s.ParseConf(request)
	if err != nil {
		klog.Errorf("failed to decode request, err: %s", err)
		return s.RetError(cnipb.ErrorCode_DECODING_FAILURE, "failed to decode request", err)
	}

	vethName := "_" + request.ContainerId[:12]

	// check ovs port
	if !s.ovsDriver.IsPortNamePresent(vethName) {
		klog.Errorf("ovs port does not exist, err: %s", err)
		return s.RetError(cnipb.ErrorCode_IO_FAILURE, "ovs port does not exist", err)
	}

	// require ipam for a new ip address
	SetEnv(request)
	err = s.ipam.ExecCheck(ctx, conf, args)
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

	conf, args, err := s.ParseConf(request)
	if err != nil {
		klog.Errorf("Parse request conf error, err: %s", err)
		return s.RetError(cnipb.ErrorCode_DECODING_FAILURE, "Parse request conf error", err)
	}

	vethName := "_" + request.ContainerId[:12]

	// delete ovs port
	if s.ovsDriver.IsPortNamePresent(vethName) {
		if err = s.ovsDriver.DeletePort(vethName); err != nil {
			klog.Errorf("delete ovs port %s error, err: %s", vethName, err)
			return s.RetError(cnipb.ErrorCode_IO_FAILURE, "delete ovs port error", err)
		}
	}

	// release allocated IP
	SetEnv(request)
	if err = s.ipam.ExecDel(ctx, conf, args); err != nil {
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

func NewCNIServer(k8sClient client.Client, datapathManager *datapath.DpManager) *CNIServer {
	s := &CNIServer{
		k8sClient: k8sClient,
		ovsDriver: datapathManager.OvsdbDriverMap[datapathManager.Info.BridgeName][datapath.LOCAL_BRIDGE_KEYWORD],
		podMTU:    datapathManager.Config.CNIConfig.MTU,
	}

	if datapathManager.Config.CNIConfig.IPAMType == constants.EverouteIPAM {
		s.ipam = eripam.NewEverouteIPAM(k8sClient, datapathManager.Info.Namespace, datapathManager.Info.GatewayIP)
	} else {
		s.ipam = eripam.NewHostLocalIPAM(datapathManager.Info.PodCIDR)
	}

	// set gateway ip address, first ip in first CIDR
	if err := SetLinkAddr(datapathManager.Info.GatewayName,
		&net.IPNet{
			IP:   datapathManager.Info.GatewayIP,
			Mask: datapathManager.Info.GatewayMask}); err != nil {
		klog.Errorf("set gateway ip address error, err:%s", err)
	}

	return s
}
