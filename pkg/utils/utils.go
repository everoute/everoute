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
	return Base64AndSha256(namespacedName.Namespace + namespacedName.Name)[:32]
}

func Base64AndSha256(input string) string {
	b := Base64Encode([]byte(input))
	hash := sha256.Sum256(b)
	return fmt.Sprintf("%x", hash)
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
