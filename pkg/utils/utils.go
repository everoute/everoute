package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	coretypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/klog"

	"github.com/everoute/everoute/pkg/constants"
)

func Base64Encode(message []byte) []byte {
	b := make([]byte, base64.StdEncoding.EncodedLen(len(message)))
	base64.StdEncoding.Encode(b, message)
	return b
}

func EncodeNamespacedName(namespacedName coretypes.NamespacedName) string {
	if namespacedName.String() == "/" || namespacedName.String() == "" {
		klog.Error("Could not encode empty namespacedName")
		return ""
	}

	// encode name and namespace with base64
	var b []byte
	b = append(b, Base64Encode([]byte(namespacedName.Namespace))...)
	b = append(b, Base64Encode([]byte(namespacedName.Name))...)

	// encode with sha256
	hash := sha256.Sum256(b)

	return fmt.Sprintf("%x", hash)[:32]
}

func GetIfaceIP(name string) (net.IP, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}
	list, err := netlink.AddrList(link, unix.AF_INET)
	if err != nil {
		return nil, err
	}
	return list[0].IP, nil
}

func GetIfaceMAC(name string) (net.HardwareAddr, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}
	return link.Attrs().HardwareAddr, nil
}

// EqualStringSlice return true when two unordered string slice have same items.
func EqualStringSlice(list1, list2 []string) bool {
	if len(list1) != len(list2) {
		return false
	}

	var s1, s2 []string
	s1 = append(s1, list1...)
	s2 = append(s2, list2...)

	sort.Strings(s1)
	sort.Strings(s2)

	for i := range s1 {
		if s1[i] != s2[i] {
			return false
		}
	}

	return true
}

var currentAgentName string

func CurrentAgentName() string {
	if currentAgentName != "" {
		return currentAgentName
	}

	content, err := ioutil.ReadFile(constants.AgentNameConfigPath)
	if err == nil {
		currentAgentName = strings.TrimSpace(string(content))
	} else {
		// use node name for agent name in kubernetes
		currentAgentName = os.Getenv(constants.AgentNodeNameENV)
	}

	klog.Infof("Current AgentName: %s", currentAgentName)
	return currentAgentName
}

var _instance *ctrlID
var _once sync.Once

type ctrlID struct {
	mutex sync.Mutex
	ids   map[uint16]bool
}

func (c *ctrlID) AddID(id uint16) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if _, ok := c.ids[id]; ok {
		return false
	}
	c.ids[id] = true

	return true
}

func getCtrlIDMap() *ctrlID {
	_once.Do(func() {
		// create map
		_instance = &ctrlID{
			mutex: sync.Mutex{},
			ids:   map[uint16]bool{},
		}
	})
	return _instance
}

func GenerateControllerID(typeID uint16) uint16 {
	ctrlIDs := getCtrlIDMap()

	var ctrlID uint16
	for {
		// genereate new ID
		err := binary.Read(rand.Reader, binary.LittleEndian, &ctrlID)
		if err != nil {
			klog.Errorf("get random ID from rand.Reader: %s", err)
			continue
		}

		// set component type
		// controller id:
		// | 4 bits component type | 12 bits random ID |
		ctrlID >>= 4
		ctrlID |= typeID << 12

		if !ctrlIDs.AddID(ctrlID) {
			continue
		}

		klog.Infof("generate controller ID: %x", ctrlID)
		return ctrlID
	}
}

func CtLabelDecode(label []byte) (uint64, uint64, uint64) {
	// Bit Order Example:
	//
	// No.1 1010 0010 1111 0001 0xA2F1  -  ovs register order
	// No.2 1000 1111 0100 0101 0x8F45  -  ovs dpctl/dump-conntrack (left-right mirror from No.1)
	// No.3 0100 0101 1000 1111 0x458F  -  netlink ct label
	//
	// label retrieve from netlink ct label, transfer it with little endian
	// In the above case, it seems as No.2
	// Since binary lib could only handle uint64, label (128 bits) split into TWO parts.
	//
	// The round number stores in high 4 bits. Here it means the right 4 bits in uint64 partA.

	partA := binary.LittleEndian.Uint64(label[0:8])
	partB := binary.LittleEndian.Uint64(label[8:16])

	var RoundMask uint64 = 0x0000_0000_0000_000F
	var flowSeq1Mask uint64 = 0x0000_0000_FFFF_FFF0
	var flowSeq2Mask uint64 = 0x0FFF_FFFF_0000_0000
	var flowSeq3MaskPartA uint64 = 0xF000_0000_0000_0000
	var flowSeq3MaskPartB uint64 = 0x0000_0000_00FF_FFFF

	roundNum := (partA & RoundMask) << 28
	flowSeq1 := (partA & flowSeq1Mask) >> 4
	flowSeq2 := (partA & flowSeq2Mask) >> (4 + 28)
	flowSeq3 := ((partA & flowSeq3MaskPartA) >> (4 + 28 + 28)) | ((partB & flowSeq3MaskPartB) << 4)

	var flowID1, flowID2, flowID3 uint64
	if flowSeq1 != 0 {
		flowID1 = roundNum | flowSeq1
	}
	if flowSeq2 != 0 {
		flowID2 = roundNum | flowSeq2
	}
	if flowSeq3 != 0 {
		flowID3 = roundNum | flowSeq3
	}
	return flowID1, flowID2, flowID3
}
