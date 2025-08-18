package action

import (
	"encoding/base64"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"github.com/everoute/everoute/pkg/constants/tr"
	"github.com/everoute/everoute/pkg/types"
)

type TRNicCfg struct {
	IfaceID string `yaml:"ifaceID"`
	// need to check ifaceID
	PortName string `yaml:"portName"`
	PortUUID string `yaml:"portUUID,omitempty"`
}

func (t *TRNicCfg) toBase64() (string, error) {
	out, err := yaml.Marshal(t)
	if err != nil {
		klog.Errorf("Failed to marshal %v to yaml: %s", t, err)
		return "", err
	}
	return base64.StdEncoding.EncodeToString(out), nil
}

func toTRNicCfg(msg string) (*TRNicCfg, error) {
	dst, err := base64.StdEncoding.DecodeString(msg)
	if err != nil {
		klog.Errorf("Failed to decode base64 string %s: %s", msg, err)
		return nil, err
	}
	res := &TRNicCfg{}
	err = yaml.Unmarshal(dst, res)
	if err != nil {
		klog.Errorf("Failed to unmarshal yaml %s to TRNicCfg: %s", string(dst), err)
		return nil, err
	}
	return res, nil
}

func getExternalIDKey(ovsBrName string, d types.NicDirect) string {
	prefix := tr.NicInExternalIDKeyPrefix
	if d == types.NicOut {
		prefix = tr.NicOutExternalIDKeyPrefix
	}

	return fmt.Sprintf("%s%s", prefix, ovsBrName)
}

func parseExternalIDKey(s string) (bool, string) {
	if strings.HasPrefix(s, tr.NicInExternalIDKeyPrefix) {
		return true, strings.TrimPrefix(s, tr.NicInExternalIDKeyPrefix)
	}
	if strings.HasPrefix(s, tr.NicOutExternalIDKeyPrefix) {
		return true, strings.TrimPrefix(s, tr.NicOutExternalIDKeyPrefix)
	}
	return false, ""
}

func getNicConfig(ovsBrName string, d types.NicDirect) (*TRNicCfg, error) {
	key := getExternalIDKey(ovsBrName, d)
	cmd := fmt.Sprintf("ovs-vsctl br-get-external-id %s %s", tr.SvcChainBridgeName, key)
	res, err := executeCommand(cmd)
	if err != nil {
		klog.Errorf("Failed to get %s externalid for key %s", tr.SvcChainBridgeName, key)
		return nil, err
	}
	if len(res) == 0 {
		return nil, nil
	}
	out, err := toTRNicCfg(res)
	if err != nil {
		klog.Errorf("Failed to convert externalid (key is %s) to vds %s trafficredirect nic config: %s", key, ovsBrName, err)
	}
	return out, err
}

func delNicConfig(ovsBrName string, d types.NicDirect) error {
	key := getExternalIDKey(ovsBrName, d)
	cmd := fmt.Sprintf("ovs-vsctl br-set-external-id %s %s", tr.SvcChainBridgeName, key)
	_, err := executeCommand(cmd)
	if err != nil {
		klog.Errorf("Failed to delete svcchain bridge externalid for key %s: %s", key, err)
		return err
	}
	return nil
}

func updateNicConfig(ovsbrName string, d types.NicDirect, c *TRNicCfg) error {
	if c == nil {
		return fmt.Errorf("param TRNicCfg is nil")
	}
	external, err := c.toBase64()
	if err != nil {
		klog.Errorf("failed to encode trafficredirect nic config for ovs bridge %s direct %s: %s", ovsbrName, d, err)
		return err
	}
	cmd := fmt.Sprintf("ovs-vsctl br-set-external-id %s %s %s", tr.SvcChainBridgeName, getExternalIDKey(ovsbrName, d), external)
	if _, err := executeCommand(cmd); err != nil {
		klog.Errorf("failed to update trafficredirect nic config %v for ovs bridge %s direct %s to external_ids: %s", *c, ovsbrName, d, err)
		return err
	}

	klog.Infof("success to update trafficredirect nic config %v for ovs bridge %s direct %s to external_ids", *c, ovsbrName, d)
	return nil
}

func getAllBridge() (sets.Set[string], error) {
	cmd := fmt.Sprintf("ovs-vsctl br-get-external-id %s", tr.SvcChainBridgeName)
	res, err := executeCommand(cmd)
	if err != nil {
		klog.Errorf("Failed to get svcchain bridge externalids: %s", err)
		return nil, err
	}
	bridges := sets.New[string]()
	externalIDs := strings.Split(res, "\n")
	for _, s := range externalIDs {
		kv := strings.SplitN(s, "=", 2)
		if len(kv) != 2 {
			klog.Warningf("invalid external_id %s, skip", s)
			continue
		}
		isBridgeKey, key := parseExternalIDKey(kv[0])
		if !isBridgeKey || key == "" {
			continue
		}
		bridges.Insert(key)
	}

	return bridges, nil
}
