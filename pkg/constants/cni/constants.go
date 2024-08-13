package cni

const (
	// overlay
	GwEpNamePrefix     = "gw-ep"
	GwEpExternalIDName = "gw-ep"
	EncapModeGeneve    = "geneve"
	GeneveHeaderLen    = 50

	// ipam
	EverouteIPAM = "everoute"
	GwIPPoolName = "everoute-built-in"

	// svc proxy
	IPSetNameNPSvcTCP = "er-npsvc-tcp"
	IPSetNameNPSvcUDP = "er-npsvc-udp"
	IPSetNameLBSvc    = "er-lbsvc"
	IPtSvcChain       = "EVEROUTE-SVC"
	IPtNPSvcChain     = "EVEROUTE-SVC-NP"

	// InternalSvcPktMarkBit pod request clusterIP svc, used in local bridge
	InternalSvcPktMarkBit = 29
	// ExternalSvcPktMarkBit nodeport/lb/clusterIP svc mark, used in uplink bridge and kernel route
	ExternalSvcPktMarkBit = 28
	// SvcLocalPktMarkBit set when ExternalTrafficPolicy=local
	SvcLocalPktMarkBit = 30

	// GroupID
	GroupIDFileSuffix       = ".groupid"
	MaxGroupIter            = 15
	BitWidthGroupIter       = 4
	GroupIDUpdateUnit       = 100
	DeleteAllGroupThreshold = 1000000

	// ct zone used by cni
	CTZoneNatBrFromLocal  = 65505
	CTZoneNatBrFromUplink = 65506
	CTZoneLocalBr         = 65510
	CTZoneUplinkBr        = 65503

	// route table number
	FromGwLocalRouteTable = 100
	SvcToGWRouteTable     = 110

	// route table priority
	LocalRulePriority        = 200
	FromGwLocalRulePriority  = 100
	SvcRulePriority          = 110
	ClusterIPSvcRulePriority = 111
	SvcLocalIPRulePriority   = 120
)
