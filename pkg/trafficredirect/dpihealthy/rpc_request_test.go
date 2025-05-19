package dpihealthy

import (
	"errors"
	"net"
	"testing"
	"time"

	. "github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/assert"

	"github.com/everoute/everoute/pkg/types"
)

type mockConn struct {
	writeCalled bool
	readResp    []byte
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	copy(b, m.readResp)
	return len(m.readResp), nil
}
func (m *mockConn) Write(b []byte) (n int, err error) {
	m.writeCalled = true
	return len(b), nil
}
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestHealthyCheck(t *testing.T) {
	tests := []struct {
		name         string
		dialErr      error
		responseJSON string
		expected     types.DPIStatus
	}{
		{
			name:     "Dial error",
			dialErr:  errors.New("connection failed"),
			expected: types.DPIUnknown,
		},
		{
			name:         "Successful Alive",
			responseJSON: `{"ec":"EOK","error":"","data":{"DPI":"alive"}}`,
			expected:     types.DPIAlive,
		},
		{
			name:         "Successful Dead",
			responseJSON: `{"ec":"EOK","error":"","data":{"DPI":"dead"}}`,
			expected:     types.DPIDead,
		},
		{
			name:         "Wrong ec",
			responseJSON: `{"ec":"FAIL","error":"some error","data":{"DPI":"alive"}}`,
			expected:     types.DPIUnknown,
		},
		{
			name:         "Missing DPI field",
			responseJSON: `{"ec":"EOK","error":"","data":{"Other":"alive"}}`,
			expected:     types.DPIUnknown,
		},
		{
			name:         "DPI module unknown",
			responseJSON: `{"ec":"EOK","error":"","data":{"DPI":"unexpected"}}`,
			expected:     types.DPIUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patch := NewPatches()
			defer patch.Reset()

			if tt.dialErr != nil {
				patch.ApplyFunc(net.DialTimeout, func(_, _ string, _ time.Duration) (net.Conn, error) {
					return nil, tt.dialErr
				})
			} else {
				patch.ApplyFunc(net.DialTimeout, func(_, _ string, _ time.Duration) (net.Conn, error) {
					return &mockConn{
						readResp: []byte(tt.responseJSON),
					}, nil
				})
			}

			result := HealthyCheck()
			assert.Equal(t, tt.expected, result)
		})
	}
}
