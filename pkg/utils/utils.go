package utils

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	coretypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/klog"
)

func Base64Encode(message []byte) []byte {
	b := make([]byte, base64.StdEncoding.EncodedLen(len(message)))
	base64.StdEncoding.Encode(b, message)
	return b
}

func EncodeNamespacedName(namespacedName coretypes.NamespacedName) string {
	klog.Info(namespacedName)
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
