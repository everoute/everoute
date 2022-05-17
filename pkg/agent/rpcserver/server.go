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
	"net"
	"os"

	"google.golang.org/grpc"
	"k8s.io/klog"

	"github.com/everoute/everoute/pkg/agent/datapath"
	pb "github.com/everoute/everoute/pkg/apis/rpc/v1alpha1"
)

const RPCSocketAddr = "/var/run/everoute/rpc.sock"
const EverouteRunPath = "/var/run/everoute"

type Server struct {
	dpManager *datapath.DpManager
	stopChan  <-chan struct{}
}

func Initialize(datapathManager *datapath.DpManager) *Server {
	s := &Server{
		dpManager: datapathManager,
	}

	return s
}

func (s *Server) Run(stopChan <-chan struct{}) {
	klog.Info("Starting Everoute RPC Server")
	s.stopChan = stopChan

	// create path
	if _, err := os.Stat(EverouteRunPath); os.IsNotExist(err) {
		if err := os.MkdirAll(EverouteRunPath, os.ModePerm); err != nil {
			klog.Fatalf("unable to create %s", EverouteRunPath)
		}
		if err := os.Chmod(EverouteRunPath, os.ModePerm); err != nil {
			klog.Fatalf("unable to chmod %s", EverouteRunPath)
		}
	}

	// remove the remaining sock file
	_, err := os.Stat(RPCSocketAddr)
	if err == nil {
		err = os.Remove(RPCSocketAddr)
		if err != nil {
			klog.Fatalf("remove remaining sock file error, err:%s", err)
			return
		}
	}

	// listen socket
	listener, err := net.Listen("unix", RPCSocketAddr)
	if err != nil {
		klog.Fatalf("Failed to bind on %s: %v", RPCSocketAddr, err)
	}

	rpcServer := grpc.NewServer()
	// register collector service
	collector := NewCollectorServer(s.dpManager, stopChan)
	pb.RegisterCollectorServer(rpcServer, collector)

	// start rpc Server
	go func() {
		if err = rpcServer.Serve(listener); err != nil {
			klog.Fatalf("Failed to serve collectorServer connections: %v", err)
		}
	}()

	klog.Info("RPC server is listening ...")
	<-s.stopChan
}
