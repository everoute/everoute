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
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-ping/ping"
	"github.com/secsy/goftp"
	"github.com/spf13/cobra"
)

func NewConnectCommand() *cobra.Command {
	var server, protocol string
	var timeout time.Duration
	var packetNum, passScore int

	cmd := &cobra.Command{
		Use:   "connect [options]",
		Short: "Connect test network connection to net-utils server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConnect(server, protocol, packetNum, passScore, timeout)
		},
	}

	cmd.PersistentFlags().IntVarP(&packetNum, "packet-num", "n", 1, "send packet numbers")
	cmd.PersistentFlags().IntVarP(&passScore, "pass-score", "o", 100, "pass score, must between 0-100")
	cmd.PersistentFlags().StringVarP(&server, "server", "s", "", "net-utils server address")
	cmd.PersistentFlags().StringVarP(&protocol, "protocol", "p", "tcp", "connection protocol")
	cmd.PersistentFlags().DurationVarP(&timeout, "timeout", "t", time.Second, "timeout for connection")

	return cmd
}

func runConnect(server string, protocol string, packetNum, passScore int, timeout time.Duration) error {
	var receive int
	var err error

	switch strings.ToLower(protocol) {
	case "tcp":
		receive, err = connectTCP(server, packetNum, timeout)
	case "udp":
		receive, err = connectUDP(server, packetNum, timeout)
	case "icmp":
		receive, err = connectICMP(server, packetNum, timeout)
	case "ftp":
		err = connectFTP(server)
		if err != nil {
			return fmt.Errorf("connect to %s: %s", server, err)
		}
		return nil
	default:
		return fmt.Errorf("unsupport protocol %s", protocol)
	}

	if err != nil {
		return fmt.Errorf("connect to %s: %s", server, err)
	}

	if 100*receive/packetNum < passScore {
		return fmt.Errorf("send %d, receive %d, score too low, %d%% (real) < %d%% (want)", packetNum, receive, 100*receive/packetNum, passScore)
	}
	return nil
}

func connectTCP(server string, num int, timeout time.Duration) (int, error) {
	conn, err := net.DialTimeout("tcp", server, timeout)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	return connectRead(conn, num, timeout)
}

func connectUDP(server string, num int, timeout time.Duration) (int, error) {
	conn, err := net.DialTimeout("udp", server, timeout)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	return connectRead(conn, num, timeout)
}

func connectICMP(server string, num int, timeout time.Duration) (int, error) {
	pinger, err := ping.NewPinger(server)
	if err != nil {
		return 0, err
	}

	pinger.SetPrivileged(true)
	pinger.Count = num
	pinger.OnRecv = func(pkt *ping.Packet) {
		fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v\n", pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt)
	}
	if timeout != 0 {
		pinger.Timeout = timeout
	}
	if err = pinger.Run(); err != nil {
		return 0, err
	}

	return pinger.Statistics().PacketsRecv, nil
}

func connectRead(conn net.Conn, num int, timeout time.Duration) (int, error) {
	if timeout != 0 {
		err := conn.SetDeadline(time.Now().Add(timeout))
		if err != nil {
			return 0, err
		}
	}

	var succeed int

	for i := 0; i < num; i++ {
		if _, err := conn.Write(nil); err != nil && err != io.EOF {
			fmt.Println(err)
			continue
		}

		var buff = [2]byte{}
		if _, err := conn.Read(buff[:]); err != nil {
			fmt.Println(err)
			continue
		}

		if string(buff[:]) != "ok" {
			fmt.Println("receive unexpect response: ", string(buff[:]))
			continue
		}

		succeed++
		fmt.Printf("connection sussess to server %s\n", conn.RemoteAddr())
	}

	return succeed, nil
}

func connectFTP(server string) error {
	config := goftp.Config{
		User:               FTPUser,
		Password:           FTPPass,
		ConnectionsPerHost: 10,
		Timeout:            10 * time.Second,
		Logger:             os.Stderr,
	}

	client, err := goftp.DialConfig(config, server)
	if err != nil {
		return err
	}
	defer client.Close()

	// download to a buffer instead of file
	buf := new(bytes.Buffer)
	err = client.Retrieve("test-ftp", buf)
	if err != nil {
		return err
	}
	return nil
}
