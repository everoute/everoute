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

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"

	"github.com/everoute/everoute/pkg/apis/exporter/v1alpha1"
)

const (
	InterfaceUuidIndex = "interface-uuid-index"
	BondInterfaceIndex = "bond-interface-index"

	LocalEndpointExpirationTime = 30
	TcpSocketExpirationTime     = 8
)

type CollectorCache struct {
	interfaceCache     cache.Indexer
	localEndpointCache cache.Store
	tcpSocketCache     cache.Store
	sFlowCounterCache  cache.Store
	BondInterfaceCache cache.Indexer
}

type Interface struct {
	uuid       string
	ifindex    uint32
	name       string
	externalID map[string]string
}

type LocalEndpoint struct {
	ip  string
	mac []byte
}

type BondInterface struct {
	uuid string
	ips  cache.Store
}

type TcpSocket struct {
	localAddr string
	localPort uint16
	peerAddr  string
	peerPort  uint16

	state   uint8
	caState uint8
	rto     uint32
	rtt     uint32
	rttVar  uint32
}

type SflowCounter struct {
	ifindex uint32

	InOctets         uint64
	InUcastPkts      uint32
	InMulticastPkts  uint32
	InBroadcastPkts  uint32
	InDiscards       uint32
	InErrors         uint32
	InUnknownProtos  uint32
	OutOctets        uint64
	OutUcastPkts     uint32
	OutMulticastPkts uint32
	OutBroadcastPkts uint32
	OutDiscards      uint32
	OutErrors        uint32
}

func sFlowCounterKeyFunc(obj interface{}) (string, error) {
	return strconv.Itoa(int(obj.(*SflowCounter).ifindex)), nil
}

func interfaceKeyFunc(obj interface{}) (string, error) {
	return strconv.Itoa(int(obj.(*Interface).ifindex)), nil
}

func bondInterfaceKeyFunc(obj interface{}) (string, error) {
	return obj.(*BondInterface).uuid, nil
}

func bondInterfaceIndexFunc(obj interface{}) ([]string, error) {
	ips := obj.(*BondInterface).ips.List()
	var out []string
	for _, ip := range ips {
		out = append(out, ip.(net.IP).String())
	}
	return out, nil
}

func localEndpointKeyFunc(obj interface{}) (string, error) {
	return obj.(*LocalEndpoint).ip, nil
}

func tcpSocketKeyFunc(obj interface{}) (string, error) {
	tcp := obj.(*TcpSocket)
	key := fmt.Sprintf("%s:%d/%s:%d", tcp.localAddr, tcp.localPort, tcp.peerAddr, tcp.peerPort)
	return key, nil
}

func interfaceUuidIndexFunc(obj interface{}) ([]string, error) {
	iface := obj.(*Interface)
	return []string{iface.uuid}, nil
}

func NewCollectorCache() *CollectorCache {
	return &CollectorCache{
		localEndpointCache: cache.NewTTLStore(localEndpointKeyFunc, time.Second*LocalEndpointExpirationTime),
		tcpSocketCache:     cache.NewTTLStore(tcpSocketKeyFunc, time.Second*TcpSocketExpirationTime),
		interfaceCache:     cache.NewIndexer(interfaceKeyFunc, cache.Indexers{InterfaceUuidIndex: interfaceUuidIndexFunc}),
		sFlowCounterCache:  cache.NewTTLStore(sFlowCounterKeyFunc, time.Second*SFlowPooling*2),
		BondInterfaceCache: cache.NewIndexer(bondInterfaceKeyFunc, cache.Indexers{BondInterfaceIndex: bondInterfaceIndexFunc}),
	}
}

func (c *CollectorCache) AddSFlowCounter(item layers.SFlowGenericInterfaceCounters) {
	err := c.sFlowCounterCache.Add(&SflowCounter{
		ifindex:          item.IfIndex,
		InOctets:         item.IfInOctets,
		InUcastPkts:      item.IfInUcastPkts,
		InMulticastPkts:  item.IfInMulticastPkts,
		InBroadcastPkts:  item.IfInBroadcastPkts,
		InDiscards:       item.IfInDiscards,
		InErrors:         item.IfInErrors,
		InUnknownProtos:  item.IfInUnknownProtos,
		OutOctets:        item.IfOutOctets,
		OutUcastPkts:     item.IfOutUcastPkts,
		OutMulticastPkts: item.IfOutMulticastPkts,
		OutBroadcastPkts: item.IfOutBroadcastPkts,
		OutDiscards:      item.IfOutDiscards,
		OutErrors:        item.IfOutErrors,
	})
	if err != nil {
		klog.Errorf("add sFlow counter cache error, err:%s", err)
	}
}

func (c *CollectorCache) FetchSocketByFlow(flow *v1alpha1.Flow) *TcpSocket {
	tcp, exist, err := c.tcpSocketCache.Get(&TcpSocket{
		localAddr: net.IP(flow.OriginTuple.Src).String(),
		localPort: uint16(flow.OriginTuple.SrcPort),
		peerAddr:  net.IP(flow.OriginTuple.Dst).String(),
		peerPort:  uint16(flow.OriginTuple.DstPort),
	})
	if exist && err == nil {
		return tcp.(*TcpSocket)
	}

	tcp, exist, err = c.tcpSocketCache.Get(&TcpSocket{
		peerAddr:  net.IP(flow.OriginTuple.Src).String(),
		peerPort:  uint16(flow.OriginTuple.SrcPort),
		localAddr: net.IP(flow.OriginTuple.Dst).String(),
		localPort: uint16(flow.OriginTuple.DstPort),
	})
	if exist && err == nil {
		return tcp.(*TcpSocket)
	}

	tcp, exist, err = c.tcpSocketCache.Get(&TcpSocket{
		peerAddr:  net.IP(flow.ReplyTuple.Src).String(),
		peerPort:  uint16(flow.ReplyTuple.SrcPort),
		localAddr: net.IP(flow.ReplyTuple.Dst).String(),
		localPort: uint16(flow.ReplyTuple.DstPort),
	})
	if exist && err == nil {
		return tcp.(*TcpSocket)
	}

	tcp, exist, err = c.tcpSocketCache.Get(&TcpSocket{
		localAddr: net.IP(flow.ReplyTuple.Src).String(),
		localPort: uint16(flow.ReplyTuple.SrcPort),
		peerAddr:  net.IP(flow.ReplyTuple.Dst).String(),
		peerPort:  uint16(flow.ReplyTuple.DstPort),
	})
	if exist && err == nil {
		return tcp.(*TcpSocket)
	}

	return nil
}

func (c *CollectorCache) AddBondIf(uuid string) {
	bond := &BondInterface{
		uuid: uuid,
		ips: cache.NewTTLStore(func(obj interface{}) (string, error) {
			return obj.(net.IP).String(), nil
		}, time.Second*TcpSocketExpirationTime*2),
	}

	err := c.BondInterfaceCache.Add(bond)
	if err != nil {
		klog.Errorf("add bond interface %+v error, err:%s", bond, err)
	}
	klog.Infof("add bond interface %+v success", bond)
}

func (c *CollectorCache) DelBondIf(uuid string) {
	_, exist, _ := c.BondInterfaceCache.Get(&BondInterface{uuid: uuid})
	if !exist {
		return
	}

	err := c.BondInterfaceCache.Delete(&BondInterface{uuid: uuid})
	if err != nil {
		klog.Errorf("delete BondInterface %d error, err:%s", uuid, err)
	}
}

func (c *CollectorCache) CheckAndAddBondIp(ifindex uint32, ipPkt gopacket.Packet) {
	// get interface uuid
	iface, exist, err := c.interfaceCache.Get(&Interface{ifindex: ifindex})
	if !exist || err != nil {
		return
	}
	// get bond interface by uuid
	bond, exist, err := c.BondInterfaceCache.Get(&BondInterface{uuid: iface.(*Interface).uuid})
	if !exist || err != nil {
		return
	}

	ip := layers.IPv4{}
	err = ip.DecodeFromBytes(ipPkt.LinkLayer().LayerPayload(), gopacket.NilDecodeFeedback)
	if err != nil {
		klog.Errorf("parse ip pkt error,err:%s", err)
		return
	}
	err = bond.(*BondInterface).ips.Add(ip.DstIP)
	if err != nil {
		klog.Errorf("Add dst ip %s to bond interface %d error, err:%s", ip.DstIP, ifindex, err)
		return
	}
	// MUST update bond struct, inner data struct(ips) update will not trigger index re-sync.
	err = c.BondInterfaceCache.Update(bond.(*BondInterface))
	if err != nil {
		klog.Errorf("sync bond interface %d error, err:%s", ifindex, err)
		return
	}
}

func (c *CollectorCache) FetchIpBondInterface(ip string) []string {
	// fetch ip from bond cache
	bonds, err := c.BondInterfaceCache.ByIndex(BondInterfaceIndex, ip)
	if err != nil {
		klog.Error(err)
		return []string{}
	}
	// out means target IP is in cache
	var out []string
	for _, bond := range bonds {
		ifs, err := c.interfaceCache.ByIndex(InterfaceUuidIndex, bond.(*BondInterface).uuid)
		if err != nil {
			continue
		}
		for _, iface := range ifs {
			out = append(out, iface.(*Interface).name)
		}
	}
	return out
}

func (c *CollectorCache) AddIface(iface *Interface) {
	err := c.interfaceCache.Add(iface)
	if err != nil {
		klog.Errorf("delete interface %s error, err:%s", iface, err)
	}
}

func (c *CollectorCache) DelIface(ifindex uint32) {
	err := c.interfaceCache.Delete(&Interface{ifindex: ifindex})
	if err != nil {
		klog.Errorf("delete interface %d error, err:%s", ifindex, err)
	}
}

func (c *CollectorCache) GetIfName(ifindex uint32) string {
	item, exist, err := c.interfaceCache.Get(&Interface{ifindex: ifindex})
	if !exist || err != nil {
		return ""
	}
	return item.(*Interface).name
}

func (c *CollectorCache) GetIfExternalID(ifindex uint32) map[string]string {
	item, exist, err := c.interfaceCache.Get(&Interface{ifindex: ifindex})
	if !exist || err != nil {
		return nil
	}
	return item.(*Interface).externalID
}

func (c *CollectorCache) IsLocalIface(ifindex uint32) bool {
	item, exist, err := c.interfaceCache.Get(&Interface{ifindex: ifindex})
	if !exist || err != nil {
		return false
	}

	if len(item.(*Interface).externalID) != 0 {
		return true
	}
	return false
}

func (c *CollectorCache) GetMac(ip string) []byte {
	item, exist, err := c.localEndpointCache.Get(&LocalEndpoint{ip: ip})

	if !exist || err != nil {
		return nil
	}

	return item.(*LocalEndpoint).mac
}

func (c *CollectorCache) AddIpMac(ip string, mac []byte) {

	err := c.localEndpointCache.Add(&LocalEndpoint{
		ip:  ip,
		mac: mac,
	})
	if err != nil {
		klog.Errorf("add to collector cache error, err: %s", err)
	}
}

func (c *CollectorCache) AddArp(arp layers.ARP) {
	c.AddIpMac(net.IP(arp.SourceProtAddress).String(), arp.SourceHwAddress)
}

func (c *CollectorCache) AddIp(pkt gopacket.Packet) {
	eth := layers.Ethernet{}
	err := eth.DecodeFromBytes(pkt.LinkLayer().LayerContents(), gopacket.NilDecodeFeedback)
	if err != nil {
		return
	}

	ip := layers.IPv4{}
	err = ip.DecodeFromBytes(pkt.LinkLayer().LayerPayload(), gopacket.NilDecodeFeedback)
	if err != nil {
		return
	}

	c.AddIpMac(ip.SrcIP.String(), eth.SrcMAC)
}
