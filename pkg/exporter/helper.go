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

package exporter

import "github.com/vishvananda/netlink"

// tcp state for conntrack, differ from tcp state in kernel socket
const (
	TcpConntrackNone = iota
	TcpConntrackSynSent
	TcpConntrackSynRecv
	TcpConntrackEstablished
	TcpConntrackFinWait
	TcpConntrackCloseWait
	TcpConntrackLastAck
	TcpConntrackTimeWait
	TcpConntrackClose
	TcpConntrackListen
)

func TcpCTStatusToSocketStatus(s uint8) uint8 {
	switch s {
	case TcpConntrackNone:
		return 0
	case TcpConntrackSynSent:
		return netlink.TCP_SYN_SENT
	case TcpConntrackSynRecv:
		return netlink.TCP_SYN_RECV
	case TcpConntrackEstablished:
		return netlink.TCP_ESTABLISHED
	case TcpConntrackFinWait:
		return netlink.TCP_FIN_WAIT1
	case TcpConntrackCloseWait:
		return netlink.TCP_CLOSE_WAIT
	case TcpConntrackLastAck:
		return netlink.TCP_LAST_ACK
	case TcpConntrackTimeWait:
		return netlink.TCP_TIME_WAIT
	case TcpConntrackClose:
		return netlink.TCP_CLOSE
	case TcpConntrackListen:
		return netlink.TCP_LISTEN
	default:
		return 0
	}
}
