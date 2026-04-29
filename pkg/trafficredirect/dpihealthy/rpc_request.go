package dpihealthy

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"k8s.io/klog/v2"

	commonlog "github.com/everoute/everoute/pkg/common/log"
	"github.com/everoute/everoute/pkg/constants/tr"
	"github.com/everoute/everoute/pkg/types"
)

const (
	SocketPath        = "/var/run/vs-controller/vs-controller.sock"
	RPCMethodName     = "channel-state"
	DPIModuleName     = "DPI"
	EverouteRequestID = 2
)

const (
	errKeyDial           = "dial"
	errKeyEncodeRequest  = "encode-request"
	errKeySendRequest    = "send-request"
	errKeyReadResponse   = "read-response"
	errKeyParseResponse  = "parse-response"
	errKeyExecuteFailure = "execute-failure"
	errKeyUnknownStatus  = "unknown-status"
	errKeyMissingModule  = "missing-module"
)

var healthyCheckErrLogger = &healthyLogger{compressors: make(map[string]*commonlog.MsgCompressor)}

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
		return logUnknown(errKeyDial, "can't connect dpi healthy check unix socket(%s): %s", SocketPath, err)
	}
	defer conn.Close()

	req := Request{
		JSONRPC: "2.0",
		Method:  RPCMethodName,
		ID:      EverouteRequestID,
	}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return logUnknown(errKeyEncodeRequest, "failed to encode request %v to json: %s", req, err)
	}

	_, err = conn.Write(reqBytes)
	if err != nil {
		return logUnknown(errKeySendRequest, "failed to send request: %s", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return logUnknown(errKeyReadResponse, "failed to get response: %s", err)
	}

	var resp Response
	err = json.Unmarshal(buf[:n], &resp)
	if err != nil {
		return logUnknown(errKeyParseResponse, "failed to parse response: %s", err)
	}

	if resp.Result.Ec != "E_OK" || resp.Result.Error != "" {
		return logUnknown(errKeyExecuteFailure, "request execute failed, ec: %s, err: %s", resp.Result.Ec, resp.Result.Error)
	}

	for k, v := range resp.Result.Data {
		if k == DPIModuleName {
			if v == string(types.DPIAlive) || v == string(types.DPIDead) {
				klog.V(4).Infof("DPI healthy check response status is %s", v)
				return types.DPIStatus(v)
			}
			return logUnknown(errKeyUnknownStatus, "DPI healthy check response status is unknown status %s", v)
		}
	}

	return logUnknown(errKeyMissingModule, "DPI healthy check response status doesn't has %s module", DPIModuleName)
}

func LogHealthyRecovered(status types.DPIStatus) {
	healthyCheckErrLogger.recover(status)
}

func logUnknown(key, format string, args ...interface{}) types.DPIStatus {
	healthyCheckErrLogger.logErrorf(key, format, args...)
	return types.DPIUnknown
}

type healthyLogger struct {
	mu          sync.Mutex
	compressors map[string]*commonlog.MsgCompressor
}

func (l *healthyLogger) logErrorf(key, format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	c, ok := l.compressors[key]
	if !ok {
		c = commonlog.NewMsgCompressor(tr.DPIHealthyLogCompressPeriod)
		l.compressors[key] = c
	}

	if msg := c.NextMessage(format, args...); msg != "" {
		klog.Errorf("%s", msg)
	}
}

func (l *healthyLogger) recover(status types.DPIStatus) {
	l.mu.Lock()
	defer l.mu.Unlock()

	keys := make([]string, 0, len(l.compressors))
	for k := range l.compressors {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	type item struct {
		key   string
		count int
	}
	items := make([]item, 0, len(keys))
	var earliest time.Time
	for _, k := range keys {
		summary, ok := l.compressors[k].Recover()
		if !ok {
			continue
		}
		if earliest.IsZero() || summary.Since.Before(earliest) {
			earliest = summary.Since
		}
		items = append(items, item{key: k, count: summary.Suppressed})
	}

	if len(items) == 0 {
		return
	}

	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, fmt.Sprintf("%s=%d", it.key, it.count))
	}
	klog.Infof(
		"DPI healthy check recover from unknown to %s after %s (suppressed by category: %s)",
		status, time.Since(earliest).Round(time.Second), strings.Join(parts, ", "),
	)
}
