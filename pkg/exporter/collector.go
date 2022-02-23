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
	"time"

	"github.com/contiv/libOpenflow/protocol"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	netlink2 "github.com/mdlayher/netlink"
	"github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"
	"github.com/vishvananda/netlink"
	"k8s.io/klog"
	"k8s.io/kubernetes/pkg/util/sysctl"

	"github.com/everoute/everoute/pkg/agent/datapath"
	"github.com/everoute/everoute/pkg/apis/exporter/v1alpha1"
)

const (
	ConntrackSampleInterval = 5
	TcpSocketSampleInterval = 5

	LocalEndpointExpirationTime = 30
	TcpSocketExpirationTime     = 8

	SflowPoolRate = 10
)

// tcp state for conntrack
const (
	TCP_CONNTRACK_NONE = iota
	TCP_CONNTRACK_SYN_SENT
	TCP_CONNTRACK_SYN_RECV
	TCP_CONNTRACK_ESTABLISHED
	TCP_CONNTRACK_FIN_WAIT
	TCP_CONNTRACK_CLOSE_WAIT
	TCP_CONNTRACK_LAST_ACK
	TCP_CONNTRACK_TIME_WAIT
	TCP_CONNTRACK_CLOSE
	TCP_CONNTRACK_LISTEN
)

type Exporter struct {
	cache    *CollectorCache
	uploader Uploader

	AgentArpChan chan protocol.ARP
	stopChan     <-chan struct{}

	datapathManager *datapath.DpManager
}

func NewExporter(uploader Uploader) *Exporter {
	e := &Exporter{
		cache:    NewCollectorCache(),
		uploader: uploader,
	}
	e.AgentArpChan = make(chan protocol.ARP, 100)

	return e
}

func (e *Exporter) StartExporter(datapathManager *datapath.DpManager, stopChan <-chan struct{}) {
	e.datapathManager = datapathManager
	e.stopChan = stopChan

	ctChan := make(chan []conntrack.Flow, 100)
	sFlowChan := make(chan layers.SFlowDatagram, 100)

	ovsMonitor := NewMonior(e.cache)
	go ovsMonitor.Run(e.stopChan)

	if err := sysctl.New().SetSysctl("net/netfilter/nf_conntrack_acct", 1); err != nil {
		klog.Fatal("Could not set net.netfilter.nf_conntrack_acct to 1, err: %s", err)
	}
	if err := sysctl.New().SetSysctl("net/netfilter/nf_conntrack_timestamp", 1); err != nil {
		klog.Fatal("Could not set net.netfilter.nf_conntrack_timestamp to 1, err: %s", err)
	}

	go e.conntractCollector(ctChan)
	go e.conntrackWorker(ctChan, e.uploader)

	go e.sFlowCollector(sFlowChan)
	go e.sFlowWorker(sFlowChan)

	go e.tcpSocketCollector()

	go e.agentArpProcess()

	<-e.stopChan
}

func (e *Exporter) tcpSocketCollector() {
	ticker := time.NewTicker(time.Second * TcpSocketSampleInterval)
	for {
		select {
		case <-ticker.C:
			info, err := netlink.SocketDiagTCPInfo(netlink.FAMILY_V4)
			if err != nil {
				klog.Errorf("fail to get tcp socket info %s", err)
			}
			for _, item := range info {
				if item.TCPInfo != nil && item.InetDiagMsg != nil {
					// filter loopback
					if item.InetDiagMsg.ID.Source.IsLoopback() || item.InetDiagMsg.ID.Destination.IsLoopback() {
						continue
					}
					// filter local
					if item.InetDiagMsg.ID.Source.Equal(item.InetDiagMsg.ID.Destination) {
						continue
					}
					_ = e.cache.tcpSocketCache.Add(&TcpSocket{
						localAddr: item.InetDiagMsg.ID.Source.String(),
						localPort: item.InetDiagMsg.ID.SourcePort,
						peerAddr:  item.InetDiagMsg.ID.Destination.String(),
						peerPort:  item.InetDiagMsg.ID.DestinationPort,
						state:     item.TCPInfo.State,
						caState:   item.TCPInfo.Ca_state,
						rto:       item.TCPInfo.Rto,
						rtt:       item.TCPInfo.Rtt,
						rttVar:    item.TCPInfo.Rttvar,
					})

					//klog.Infof("tcp %s:%d rto: %d", item.InetDiagMsg.ID.Source.String(), item.InetDiagMsg.ID.SourcePort, item.TCPInfo.Rto)
				}
			}

		case <-e.stopChan:
			return
		}
	}
}

func (e *Exporter) agentArpProcess() {
	for {
		select {
		case arp := <-e.AgentArpChan:
			e.cache.AddAgentArp(arp)
		case <-e.stopChan:
			return
		}
	}
}

func (e *Exporter) sFlowCollector(flow chan layers.SFlowDatagram) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: SFlowPort,
	})

	if err != nil {
		klog.Fatal("Listen failed,", err)
		return
	}
	for {
		var data [100000]byte // MAX MTU
		n, addr, err := udpConn.ReadFromUDP(data[:])
		if err != nil {
			klog.Errorf("Read from udp server:%s failed,err:%s", addr, err)
			continue
		}
		go func() {
			raw := layers.SFlowDatagram{}
			err = raw.DecodeFromBytes(data[:n], gopacket.NilDecodeFeedback)
			if err != nil {
				klog.Errorf("decode sflow datagram error, err:%s", err)
				return
			}
			flow <- raw
		}()
	}
}

func (e *Exporter) ctFilter(ct conntrack.Flow) bool {
	// skip loopBack connections
	if ct.TupleOrig.IP.SourceAddress.IsLoopback() && ct.TupleOrig.IP.DestinationAddress.IsLoopback() {
		return true
	}

	// skip time_wait tcp flow
	if ct.TupleOrig.Proto.Protocol == uint8(layers.IPProtocolTCP) {
		if ct.ProtoInfo.TCP != nil && ct.ProtoInfo.TCP.State == TCP_CONNTRACK_TIME_WAIT {
			return true
		}
	}

	// skip local connections
	if ct.TupleOrig.IP.SourceAddress.String() == ct.TupleOrig.IP.DestinationAddress.String() &&
		ct.TupleReply.IP.SourceAddress.String() == ct.TupleReply.IP.DestinationAddress.String() &&
		ct.TupleOrig.IP.SourceAddress.String() == ct.TupleReply.IP.DestinationAddress.String() {
		return true
	}

	return false
}

func (e *Exporter) ctItemToFlow(ct conntrack.Flow) *v1alpha1.Flow {
	flow := &v1alpha1.Flow{
		Protocol: uint32(ct.TupleOrig.Proto.Protocol),
		OriginTuple: &v1alpha1.FlowTuple{
			Src:     ct.TupleOrig.IP.SourceAddress,
			Dst:     ct.TupleOrig.IP.DestinationAddress,
			EthSrc:  e.cache.GetMac(ct.TupleOrig.IP.SourceAddress.String()),
			SrcPort: uint32(ct.TupleOrig.Proto.SourcePort),
			DstPort: uint32(ct.TupleOrig.Proto.DestinationPort),
		},
		ReplyTuple: &v1alpha1.FlowTuple{
			Src:     ct.TupleReply.IP.SourceAddress,
			Dst:     ct.TupleReply.IP.DestinationAddress,
			EthSrc:  e.cache.GetMac(ct.TupleReply.IP.SourceAddress.String()),
			SrcPort: uint32(ct.TupleReply.Proto.SourcePort),
			DstPort: uint32(ct.TupleReply.Proto.DestinationPort),
		},
		OriginCounter: &v1alpha1.FlowCounter{
			Packets: ct.CountersOrig.Packets,
			Bytes:   ct.CountersOrig.Bytes,
		},
		ReplyCounter: &v1alpha1.FlowCounter{
			Packets: ct.CountersReply.Packets,
			Bytes:   ct.CountersReply.Bytes,
		},
		OriginDir:   0,
		StartTime:   uint64(ct.Timestamp.Start.Unix()),
		UpdateTime:  uint64(time.Now().Unix()),
		CtId:        ct.ID,
		CtTimeout:   ct.Timeout,
		CtZone:      uint32(ct.Zone),
		CtUse:       ct.Use,
		CtMark:      ct.Mark,
		CtStatus:    uint32(ct.Status.Value),
		CtLabel:     ct.Labels,
		CtLabelMask: ct.LabelsMask,
	}
	// calculate ct direction
	if e.cache.GetMac(ct.TupleOrig.IP.SourceAddress.String()) == nil &&
		e.cache.GetMac(ct.TupleOrig.IP.DestinationAddress.String()) == nil {
		flow.OriginDir = 2
	}
	if e.cache.GetMac(ct.TupleOrig.IP.SourceAddress.String()) != nil {
		flow.OriginDir = 1
	}
	if e.cache.GetMac(ct.TupleOrig.IP.DestinationAddress.String()) != nil {
		flow.OriginDir = 0
	}

	// fetch socket info into flow
	if flow.Protocol == uint32(layers.IPProtocolTCP) {
		tcpSocket := e.cache.FetchSocketByFlow(flow)
		if tcpSocket != nil {
			flow.ProtocolInfo = &v1alpha1.ProtocolInfo{
				TcpInfo: &v1alpha1.TcpInfo{
					State:   uint32(tcpSocket.state),
					CaState: uint32(tcpSocket.caState),
					Rto:     tcpSocket.rto,
					Rtt:     tcpSocket.rtt,
					RttVar:  tcpSocket.rttVar,
				},
			}
		}
	}

	return flow
}

func (e *Exporter) conntrackWorker(channel chan []conntrack.Flow, uploader Uploader) {
	for {
		select {
		case flows := <-channel:
			flow := &v1alpha1.FlowMessage{
				Flow: []*v1alpha1.Flow{},
			}
			for _, f := range flows {
				// filter un-ness flow
				if e.ctFilter(f) {
					continue
				}
				flow.Flow = append(flow.Flow, e.ctItemToFlow(f))
			}
			uploader.Flow(flow)
		case <-e.stopChan:
			return
		}
	}

}

func (e *Exporter) sFlowWorker(channel chan layers.SFlowDatagram) {
	for {
		select {
		case flow := <-channel:
			// handle flow sample packet
			pktMsg := &v1alpha1.PktMessage{}
			for _, sample := range flow.FlowSamples {
				pktMsg.SampleRate = sample.SamplingRate
				pktMsg.SamplePool = sample.SamplePool
				pktMsg.Dropped += sample.Dropped
				for _, record := range sample.Records {
					switch record.(type) {
					case layers.SFlowRawPacketFlowRecord:
						if record.(layers.SFlowRawPacketFlowRecord).Header.LinkLayer().LayerType() == layers.LayerTypeEthernet {
							packet := record.(layers.SFlowRawPacketFlowRecord).Header
							switch packet.Layers()[1].LayerType() {
							case layers.LayerTypeARP:
								arp := layers.ARP{}
								err := arp.DecodeFromBytes(packet.Layers()[1].LayerContents(), gopacket.NilDecodeFeedback)
								if err != nil || arp.AddrType != layers.LinkTypeEthernet {
									continue
								}
								// add to cache
								if e.cache.IsLocalIface(sample.InputInterface) {
									e.cache.AddArp(arp)
								}
								pktMsg.RawArp = append(pktMsg.RawArp, packet.Data())
							case layers.LayerTypeIPv4:
								if e.cache.IsLocalIface(sample.InputInterface) {
									e.cache.AddIp(packet)
								}
								pktMsg.RawIp = append(pktMsg.RawIp, packet.Data())
							default:
								fmt.Println(packet.Layers()[1].LayerType())
							}
						}
					}
				}
			}
			if len(pktMsg.RawArp) != 0 || len(pktMsg.RawIp) != 0 {
				e.uploader.SFlowSample(pktMsg)
			}

			// handle counter sample flow
			counterMsg := &v1alpha1.CounterMessage{}
			for _, sample := range flow.CounterSamples {
				for _, record := range sample.Records {
					switch record.(type) {
					case layers.SFlowGenericInterfaceCounters:
						item := record.(layers.SFlowGenericInterfaceCounters)
						counter, exist, err := e.cache.sflowCounterCache.Get(&SflowCounter{ifindex: item.IfIndex})
						if !exist || err != nil {
							e.cache.AddSFlowCounter(item)
							continue
						}
						counterLast := counter.(*SflowCounter)
						counterMsg.Counter = append(counterMsg.Counter, &v1alpha1.Counter{
							Ifname:           e.cache.GetIfName(item.IfIndex),
							ExternalId:       e.cache.GetIfExternalID(item.IfIndex),
							Type:             item.IfType,
							LinkSpeed:        item.IfSpeed,
							Direction:        item.IfDirection,
							Status:           item.IfStatus,
							InOctets:         item.IfInOctets - counterLast.InOctets,
							InUcastPkts:      item.IfInUcastPkts - counterLast.InUcastPkts,
							InMulticastPkts:  item.IfInMulticastPkts - counterLast.InMulticastPkts,
							InBroadcastPkts:  item.IfInBroadcastPkts - counterLast.InBroadcastPkts,
							InDiscards:       item.IfInDiscards - counterLast.InDiscards,
							InErrors:         item.IfInErrors - counterLast.InErrors,
							InUnknownProtos:  item.IfInUnknownProtos - counterLast.InUnknownProtos,
							OutOctets:        item.IfOutOctets - counterLast.OutOctets,
							OutUcastPkts:     item.IfOutUcastPkts - counterLast.OutUcastPkts,
							OutMulticastPkts: item.IfOutMulticastPkts - counterLast.OutMulticastPkts,
							OutBroadcastPkts: item.IfOutBroadcastPkts - counterLast.OutBroadcastPkts,
							OutDiscards:      item.IfOutDiscards - counterLast.OutDiscards,
							OutErrors:        item.IfOutErrors - counterLast.OutErrors,
							PromiscuousMode:  item.IfPromiscuousMode,
						})
						e.cache.AddSFlowCounter(item)
					}
				}
			}
			if len(counterMsg.Counter) != 0 {
				e.uploader.SFlowCounter(counterMsg)
			}
		case <-e.stopChan:
			return
		}
	}
}

func (e *Exporter) ctEventHandle(c chan conntrack.Event) {
	for {
		select {
		case event := <-c:
			if event.Type == conntrack.EventDestroy && !e.ctFilter(*event.Flow) {
				flow := e.ctItemToFlow(*event.Flow)
				flowMsg := &v1alpha1.FlowMessage{
					Flow: []*v1alpha1.Flow{flow},
				}
				e.uploader.Flow(flowMsg)
			}
		case <-e.stopChan:
			return
		}
	}
}

func (e *Exporter) conntractCollector(ct chan []conntrack.Flow) {
	// open conntrack connection
	eventConn, err := conntrack.Dial(nil)
	if err != nil {
		klog.Fatal(err)
	}
	defer eventConn.Close()
	dumpConn, err := conntrack.Dial(nil)
	if err != nil {
		klog.Fatal(err)
	}
	defer dumpConn.Close()

	// add event handle
	eventCh := make(chan conntrack.Event, 1024)
	_, err = eventConn.Listen(eventCh, 1, append(netfilter.GroupsCT))
	if err != nil {
		klog.Fatal(err)
	}
	err = eventConn.SetOption(netlink2.ListenAllNSID, true)
	if err != nil {
		klog.Fatal(err)
	}
	go e.ctEventHandle(eventCh)

	// dump all ct flow periodically
	ticker := time.NewTicker(time.Second * ConntrackSampleInterval)
	for {
		select {
		case <-ticker.C:
			flows, err := dumpConn.Dump()
			if err != nil {
				klog.Errorf("dump flows: %s", err)
			}
			ct <- flows
		case <-e.stopChan:
			return
		}
	}
}
