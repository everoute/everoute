package utils

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	coretypes "k8s.io/apimachinery/pkg/types"
	typeuuid "k8s.io/apimachinery/pkg/util/uuid"
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

func ReadOrGenerateAgentName() string {
	content, err := ioutil.ReadFile(constants.AgentNameConfigPath)
	if err == nil {
		return string(content)
	}

	name := string(typeuuid.NewUUID())

	err = os.MkdirAll(filepath.Dir(constants.AgentNameConfigPath), 0644)
	if err != nil {
		klog.Fatalf("while write name %s: %s", name, err)
	}

	err = ioutil.WriteFile(constants.AgentNameConfigPath, []byte(name), 0644)
	if err != nil {
		klog.Fatalf("while write name %s: %s", name, err)
	}

	return name
}
