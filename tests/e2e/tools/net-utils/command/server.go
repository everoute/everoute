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

package command

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"

	filedriver "github.com/goftp/file-driver"
	"github.com/goftp/server"
	"github.com/j-keck/arping"
	"github.com/spf13/cobra"
	"k8s.io/klog"
)

const (
	FTPUser = "admin"
	FTPPass = "123456"
)

func NewServerCommand() *cobra.Command {
	var udpPorts, tcpPorts []int
	var daemon, discover bool
	var ftpServer string

	cmd := &cobra.Command{
		Use:   "server [options]",
		Short: "Server start an udp/tcp server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return start(daemon, func() error {
				runServer(udpPorts, tcpPorts, discover, ftpServer)
				return nil
			})
		},
	}

	cmd.PersistentFlags().BoolVarP(&daemon, "daemon", "d", false, "run backend as daemon")
	cmd.PersistentFlags().BoolVarP(&discover, "discover", "s", false, "send arp packets to help discover")
	cmd.PersistentFlags().IntSliceVarP(&udpPorts, "udp-ports", "u", nil, "set listen udp ports")
	cmd.PersistentFlags().IntSliceVarP(&tcpPorts, "tcp-ports", "t", nil, "set listen tcp ports")
	cmd.PersistentFlags().StringVarP(&ftpServer, "ftp-server", "f", "", "set ftp listen ip")

	return cmd
}

func start(daemon bool, runable func() error) error {
	if !daemon || os.Getenv("FORKED") == "true" {
		return runable()
	}
	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Env = append(os.Environ(), "FORKED=true")
	return cmd.Start()
}

func runServer(udpPorts, tcpPorts []int, discover bool, ftpServer string) {
	wg := &sync.WaitGroup{}
	wg.Add(len(udpPorts) + len(tcpPorts))

	for _, port := range udpPorts {
		go serveUDP(port, wg)
	}

	for _, port := range tcpPorts {
		go serveTCP(port, wg)
	}

	if discover {
		go arpDiscover()
	}

	if ftpServer != "" {
		wg.Add(1)
		go serverFTP(ftpServer)
	}

	wg.Wait()
}

func arpDiscover() {
	for {
		ifis, err := net.Interfaces()
		if err != nil {
			fmt.Printf("can't get interface: %s\n", err)
		}

		for _, ifi := range ifis {
			if ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&net.FlagUp == 0 {
				// ignore loopback and down interface
				continue
			}
			// todo: ignore interface that only contains ipv6 addr
			if addrs, err := ifi.Addrs(); err != nil || len(addrs) == 0 {
				// ignore no address interface
				continue
			}

			fmt.Println("send arp packets on interface", ifi.Name)
			ips, err := ifi.Addrs()
			for _, ip := range ips {
				fmt.Printf("send arp packets on: %s\n", ip)
				ipAddr, _, _ := net.ParseCIDR(ip.String())
				err = arping.GratuitousArpOverIfaceByName(ipAddr, ifi.Name)
				if err != nil {
					fmt.Printf("get error while arping, err: %s\n", err)
				}
			}
		}

		// wait 1s every send arp packets
		time.Sleep(time.Second)
	}
}

func serveTCP(port int, wg *sync.WaitGroup) {
	defer wg.Done()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			klog.Errorf("unexpect error will accept")
			continue
		}
		go handleTCP(conn)
	}
}

func serveUDP(port int, wg *sync.WaitGroup) {
	defer wg.Done()

	listener, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	for {
		_, addr, err := listener.ReadFromUDP(nil)
		if err != nil {
			klog.Errorf("unexpect error will accept")
			continue
		}
		klog.Infof("send udp packet ok from %s to %s", listener.LocalAddr(), addr)

		_, err = listener.WriteToUDP([]byte("ok"), addr)
		if err != nil {
			klog.Errorf("unable write udp to %s", addr)
		}
	}
}

func handleTCP(conn net.Conn) {
	defer conn.Close()

	for {
		if _, err := conn.Read(nil); err != nil {
			klog.Errorf("unable read tcp from %s", conn.RemoteAddr())
			break
		}
		klog.Infof("send tcp packet ok from %s to %s", conn.LocalAddr(), conn.RemoteAddr())

		_, err := conn.Write([]byte("ok"))
		if err != nil {
			klog.Errorf("unable write tcp to %s", conn.RemoteAddr())
			break
		}
	}
}

func serverFTP(host string) {
	klog.Infof("start ftp... host: %s", host)
	root := "/ftp"
	if root == "" {
		klog.Fatalf("Please set a root to serve with -root")
	}

	factory := &filedriver.FileDriverFactory{
		RootPath: root,
		Perm:     server.NewSimplePerm("user", "group"),
	}

	opts := &server.ServerOpts{
		Factory:  factory,
		Port:     21,
		Hostname: host,
		Auth:     &server.SimpleAuth{Name: FTPUser, Password: FTPPass},
	}

	klog.Infof("Starting ftp server on %v:%v", opts.Hostname, opts.Port)
	klog.Infof("Username %v, Password %v", FTPUser, FTPPass)
	server := server.NewServer(opts)
	err := server.ListenAndServe()
	if err != nil {
		klog.Fatalf("Error starting server:", err)
	}
	err = connectFTP(host)
	if err != nil {
		klog.Fatal("Error connect to server")
	}
}
