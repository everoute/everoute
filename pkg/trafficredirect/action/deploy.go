package action

import (
	"errors"
	"fmt"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	"github.com/everoute/everoute/pkg/config"
	"github.com/everoute/everoute/pkg/types"
)

var NicNotfound = fmt.Errorf("trafficredirect nic not found")

func Reset(cfg *config.AgentConfig) error {
	bridges, err := getAllBridge()
	if err != nil {
		return err
	}
	if bridges == nil {
		bridges = sets.New[string]()
	}

	newCfg := make(map[string]*config.TRConfig, 0)
	if cfg != nil && cfg.VdsConfigs != nil {
		for vds := range cfg.VdsConfigs {
			if len(cfg.VdsConfigs[vds].TrafficRedirects) == 0 {
				continue
			}
			br := cfg.VdsConfigs[vds].BrideName
			bridges.Insert(br)
			// only support one
			newCfg[br] = &cfg.VdsConfigs[vds].TrafficRedirects[0]
		}
	}

	for _, br := range bridges.UnsortedList() {
		if err := processVds(br, newCfg[br]); err != nil {
			if errors.Is(err, NicNotfound) {
				// skip for svm shutdown
				klog.Warningf("Skip to process ovs bridge %s trafficredirect nic, because nic not found, config is %v", br, newCfg[br])
				continue
			}
			klog.Errorf("Failed to process ovs bridge %s trafficredirect nic, config is %v", br, newCfg[br])
			return err
		}
		klog.Infof("Success to process ovs bridge %s trafficredirect nic, config is %v", br, newCfg[br])
	}
	return nil
}

func processVds(ovsbrName string, cfg *config.TRConfig) error {
	if cfg == nil {
		return ovsbrUnmountTrafficRedirect(ovsbrName)
	}

	oldNicIn, err := getNicConfig(ovsbrName, types.NicIn)
	if err != nil {
		return err
	}
	if oldNicIn != nil && oldNicIn.IfaceID != cfg.NicIn {
		if err := ovsbrUnmountTrafficRedirect(ovsbrName, types.NicIn); err != nil {
			return err
		}
	}
	oldNicOut, err := getNicConfig(ovsbrName, types.NicOut)
	if err != nil {
		return err
	}
	if oldNicOut != nil && oldNicOut.IfaceID != cfg.NicOut {
		if err := ovsbrUnmountTrafficRedirect(ovsbrName, types.NicOut); err != nil {
			return err
		}
	}

	ifaceName, err := findTrafficRedirectNic(ovsbrName, cfg.NicIn, types.NicIn)
	if err != nil {
		return err
	}
	if err := MountTRNic(ovsbrName, ifaceName, cfg.NicIn, types.NicIn); err != nil {
		return err
	}
	klog.Infof("Success to mount trafficeredirect nic(ifaceID: %s) to ovs bridge %s direct %s", cfg.NicIn, ovsbrName, types.NicIn)

	ifaceName, err = findTrafficRedirectNic(ovsbrName, cfg.NicOut, types.NicOut)
	if err != nil {
		return err
	}
	if err := MountTRNic(ovsbrName, ifaceName, cfg.NicOut, types.NicOut); err != nil {
		return err
	}
	klog.Infof("Success to mount trafficeredirect nic(ifaceID: %s) to ovs bridge %s direct %s", cfg.NicIn, ovsbrName, types.NicIn)
	return nil
}

func ovsbrUnmountTrafficRedirect(ovsbrName string, directs ...types.NicDirect) error {
	if err := DelTRNicFlows(ovsbrName); err != nil {
		return err
	}
	if len(directs) == 0 || directs[0] == types.NicIn {
		if err := UnmountTRNic(ovsbrName, types.NicIn); err != nil {
			klog.Errorf("Failed to unmount ovs bridge %s trafficredirect nic direct %s: %s", ovsbrName, types.NicIn, err)
			return err
		}
		klog.Infof("Success to unmount ovs bridge %s trafficredirect nic direct %s", ovsbrName, types.NicIn)
	}

	if len(directs) == 0 || directs[0] == types.NicOut {
		if err := UnmountTRNic(ovsbrName, types.NicOut); err != nil {
			klog.Errorf("Failed to unmount ovs bridge %s trafficredirect nic direct %s: %s", ovsbrName, types.NicOut, err)
			return err
		}
		klog.Infof("Success to unmount ovs bridge %s trafficredirect nic direct %s", ovsbrName, types.NicOut)
	}
	return nil
}
