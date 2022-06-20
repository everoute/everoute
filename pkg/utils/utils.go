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
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/alexflint/go-filemutex"
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

const controllerIDPath = "/var/lib/everoute/controllerID"

var _instance *filemutex.FileMutex
var _once sync.Once

func getCtrlPathMutex() *filemutex.FileMutex {
	_once.Do(func() {
		// create path
		if _, err := os.Stat(controllerIDPath); os.IsNotExist(err) {
			if err := os.MkdirAll(controllerIDPath, os.ModePerm); err != nil {
				klog.Fatalf("fail to create %s", controllerIDPath)
			}
			if err := os.Chmod(controllerIDPath, os.ModePerm); err != nil {
				klog.Fatalf("fail to chmod %s", controllerIDPath)
			}
		}

		// use file mutex to ensure cocurrency
		mutex, err := filemutex.New(path.Join(controllerIDPath, "lock"))
		if err != nil {
			klog.Fatal("Fail to create ControllerID file lock")
		}
		_instance = mutex
	})
	return _instance
}

func GenerateControllerID() uint16 {
	mutex := getCtrlPathMutex()

	_ = mutex.Lock()
	defer func() {
		_ = mutex.Unlock()
	}()

	var ctrlID uint16
	for {
		// genereate new ID
		err := binary.Read(rand.Reader, binary.LittleEndian, &ctrlID)
		if err != nil {
			klog.Errorf("get random ID from rand.Reader: %s", err)
			continue
		}
		targetFile := path.Join(controllerIDPath, strconv.Itoa(int(ctrlID)))

		// check if id existed
		if _, err := os.Stat(targetFile); err == nil {
			continue
		}

		// record file in path
		if _, err := os.Create(targetFile); err != nil {
			klog.Errorf("create ctrlID file %s error: %s", targetFile, err)
			continue
		}

		return ctrlID
	}
}
