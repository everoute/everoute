package dpihealthy

import (
	"encoding/json"
	"net"

	"k8s.io/klog/v2"

	"github.com/everoute/everoute/pkg/constants/tr"
	"github.com/everoute/everoute/pkg/types"
)

const (
	SocketPath        = "/var/run/vs-controller/vs-controller.sock"
	RPCMethodName     = "channel-state"
	DPIModuleName     = "DPI"
	EverouteRequestID = 2
)

type Request struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	// request id
	ID int `json:"id"`
}

type Result struct {
	Ec    string            `json:"ec"`
	Error string            `json:"error"`
	Data  map[string]string `json:"data"`
}

type Response struct {
	Result Result `json:"result"`
}

func HealthyCheck() types.DPIStatus {
	conn, err := net.DialTimeout("unix", SocketPath, tr.DPIHealthyCheckTimeout)
	if err != nil {
		klog.Errorf("Can't connect dpi healthy check unix socket(%s): %s", SocketPath, err)
		return types.DPIUnknown
	}
	defer conn.Close()

	req := Request{
		JSONRPC: "2.0",
		Method:  RPCMethodName,
		ID:      EverouteRequestID,
	}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		klog.Errorf("Failed to encode request %v to json: %s", req, err)
		return types.DPIUnknown
	}

	_, err = conn.Write(reqBytes)
	if err != nil {
		klog.Errorf("Failed to send request: %s", err)
		return types.DPIUnknown
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		klog.Errorf("Failed to get response: %s", err)
		return types.DPIUnknown
	}

	var resp Response
	err = json.Unmarshal(buf[:n], &resp)
	if err != nil {
		klog.Errorf("Failed to parse response: %s", err)
		return types.DPIUnknown
	}

	if resp.Result.Ec != "E_OK" || resp.Result.Error != "" {
		klog.Errorf("Request execute failed, ec: %s, err: %s", resp.Result.Ec, resp.Result.Error)
		return types.DPIUnknown
	}

	for k, v := range resp.Result.Data {
		if k == DPIModuleName {
			if v == string(types.DPIAlive) || v == string(types.DPIDead) {
				klog.V(4).Infof("DPI healthy check response status is %s", v)
				return types.DPIStatus(v)
			}
			klog.Infof("DPI healthy check response status is unknown status %s", v)
			return types.DPIUnknown
		}
	}

	klog.Errorf("DPI Healthy check response status doesn't has %s module", DPIModuleName)
	return types.DPIUnknown
}
