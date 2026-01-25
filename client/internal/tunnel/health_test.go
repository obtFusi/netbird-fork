package tunnel

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestDefaultHealthCheckConfig(t *testing.T) {
	config := DefaultHealthCheckConfig()

	if config.Interval != DefaultHealthCheckInterval {
		t.Errorf("Interval = %v, want %v", config.Interval, DefaultHealthCheckInterval)
	}

	if config.HandshakeTimeout != DefaultHandshakeTimeout {
		t.Errorf("HandshakeTimeout = %v, want %v", config.HandshakeTimeout, DefaultHandshakeTimeout)
	}

	if config.GRPCPingTimeout != DefaultGRPCPingTimeout {
		t.Errorf("GRPCPingTimeout = %v, want %v", config.GRPCPingTimeout, DefaultGRPCPingTimeout)
	}

	if config.ConsecutiveFailures != DefaultConsecutiveFailures {
		t.Errorf("ConsecutiveFailures = %v, want %v", config.ConsecutiveFailures, DefaultConsecutiveFailures)
	}
}

func TestHealthStatusString(t *testing.T) {
	tests := []struct {
		status   HealthStatus
		expected string
	}{
		{HealthStatusUnknown, "unknown"},
		{HealthStatusHealthy, "healthy"},
		{HealthStatusDegraded, "degraded"},
		{HealthStatusUnhealthy, "unhealthy"},
		{HealthStatus(99), "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.status.String(); got != tt.expected {
				t.Errorf("HealthStatus.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestNewHealthChecker(t *testing.T) {
	tests := []struct {
		name   string
		config HealthCheckConfig
	}{
		{
			name:   "default config",
			config: DefaultHealthCheckConfig(),
		},
		{
			name: "zero values get defaults",
			config: HealthCheckConfig{
				Interval:            0,
				HandshakeTimeout:    0,
				GRPCPingTimeout:     0,
				ConsecutiveFailures: 0,
			},
		},
		{
			name: "custom config",
			config: HealthCheckConfig{
				Interval:            10 * time.Second,
				HandshakeTimeout:    1 * time.Minute,
				GRPCPingTimeout:     5 * time.Second,
				ConsecutiveFailures: 5,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hc := NewHealthChecker(tt.config)
			if hc == nil {
				t.Error("NewHealthChecker returned nil")
			}
		})
	}
}

func TestHealthCheckerStartStop(t *testing.T) {
	config := HealthCheckConfig{
		Interval:            100 * time.Millisecond,
		ConsecutiveFailures: 3,
	}

	hc := NewHealthChecker(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start
	if err := hc.Start(ctx); err != nil {
		t.Errorf("Start() error = %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Starting again should fail
	if err := hc.Start(ctx); err == nil {
		t.Error("Start() should fail when already running")
	}

	// Stop
	hc.Stop()

	time.Sleep(50 * time.Millisecond)

	// Should not be running
	hc.mu.RLock()
	running := hc.running
	hc.mu.RUnlock()

	if running {
		t.Error("Expected health checker to be stopped")
	}
}

func TestHealthCheckerCheck(t *testing.T) {
	config := DefaultHealthCheckConfig()
	hc := NewHealthChecker(config)

	ctx := context.Background()

	// With no checkers configured, all should pass
	result := hc.Check(ctx)

	if result.Status != HealthStatusHealthy {
		t.Errorf("Status = %v, want %v", result.Status, HealthStatusHealthy)
	}

	if !result.InterfaceUp {
		t.Error("InterfaceUp should be true when not configured")
	}

	if !result.GRPCAlive {
		t.Error("GRPCAlive should be true when not configured")
	}

	if !result.HandshakeOK {
		t.Error("HandshakeOK should be true when not configured")
	}
}

func TestHealthCheckerWithInterfaceChecker(t *testing.T) {
	config := DefaultHealthCheckConfig()
	hc := NewHealthChecker(config)

	// Interface down
	hc.SetInterfaceChecker(func() (bool, error) {
		return false, nil
	})

	ctx := context.Background()
	result := hc.Check(ctx)

	if result.Status != HealthStatusUnhealthy {
		t.Errorf("Status = %v, want %v", result.Status, HealthStatusUnhealthy)
	}

	if result.InterfaceUp {
		t.Error("InterfaceUp should be false")
	}

	// Interface up
	hc.SetInterfaceChecker(func() (bool, error) {
		return true, nil
	})

	result = hc.Check(ctx)

	if result.Status != HealthStatusHealthy {
		t.Errorf("Status = %v, want %v", result.Status, HealthStatusHealthy)
	}

	if !result.InterfaceUp {
		t.Error("InterfaceUp should be true")
	}

	// Interface error
	hc.SetInterfaceChecker(func() (bool, error) {
		return false, errors.New("interface error")
	})

	result = hc.Check(ctx)

	if result.Status != HealthStatusUnhealthy {
		t.Errorf("Status = %v, want %v", result.Status, HealthStatusUnhealthy)
	}

	if result.LastError == nil {
		t.Error("LastError should be set")
	}
}

func TestHealthCheckerWithGRPCChecker(t *testing.T) {
	config := HealthCheckConfig{
		GRPCPingTimeout:     100 * time.Millisecond,
		ConsecutiveFailures: 3,
	}
	hc := NewHealthChecker(config)

	// gRPC alive
	hc.SetGRPCChecker(func(ctx context.Context) error {
		return nil
	})

	ctx := context.Background()
	result := hc.Check(ctx)

	if !result.GRPCAlive {
		t.Error("GRPCAlive should be true")
	}

	// gRPC error (degraded, not unhealthy)
	hc.SetGRPCChecker(func(ctx context.Context) error {
		return errors.New("grpc error")
	})

	result = hc.Check(ctx)

	if result.GRPCAlive {
		t.Error("GRPCAlive should be false")
	}

	// Status should be degraded (gRPC alone doesn't make unhealthy)
	if result.Status != HealthStatusDegraded {
		t.Errorf("Status = %v, want %v", result.Status, HealthStatusDegraded)
	}
}

func TestHealthCheckerWithHandshakeChecker(t *testing.T) {
	config := HealthCheckConfig{
		HandshakeTimeout:    1 * time.Minute,
		ConsecutiveFailures: 3,
	}
	hc := NewHealthChecker(config)

	// Fresh handshake
	hc.SetHandshakeChecker(func() (time.Time, error) {
		return time.Now().Add(-30 * time.Second), nil
	})

	ctx := context.Background()
	result := hc.Check(ctx)

	if !result.HandshakeOK {
		t.Error("HandshakeOK should be true")
	}

	// Stale handshake
	hc.SetHandshakeChecker(func() (time.Time, error) {
		return time.Now().Add(-2 * time.Minute), nil
	})

	result = hc.Check(ctx)

	if result.HandshakeOK {
		t.Error("HandshakeOK should be false")
	}

	// Status should be degraded
	if result.Status != HealthStatusDegraded {
		t.Errorf("Status = %v, want %v", result.Status, HealthStatusDegraded)
	}
}

func TestHealthCheckerOnUnhealthyCallback(t *testing.T) {
	config := HealthCheckConfig{
		Interval:            50 * time.Millisecond,
		ConsecutiveFailures: 2,
	}

	hc := NewHealthChecker(config)

	callbackCalled := int32(0)
	hc.SetOnUnhealthy(func() {
		atomic.AddInt32(&callbackCalled, 1)
	})

	// Set interface to always fail
	hc.SetInterfaceChecker(func() (bool, error) {
		return false, nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_ = hc.Start(ctx)

	// Wait for consecutive failures
	time.Sleep(200 * time.Millisecond)

	hc.Stop()

	if atomic.LoadInt32(&callbackCalled) == 0 {
		t.Error("OnUnhealthy callback should have been called")
	}
}

func TestHealthCheckerGetLastResult(t *testing.T) {
	config := DefaultHealthCheckConfig()
	hc := NewHealthChecker(config)

	// Initially nil
	if result := hc.GetLastResult(); result != nil {
		t.Error("GetLastResult() should return nil before any check")
	}

	// Perform a check
	ctx := context.Background()
	_ = hc.Check(ctx)

	// Now should have a result
	result := hc.GetLastResult()
	if result == nil {
		t.Error("GetLastResult() should return result after check")
	}

	if result.Status != HealthStatusHealthy {
		t.Errorf("Status = %v, want %v", result.Status, HealthStatusHealthy)
	}
}

func TestHealthCheckerGetStatus(t *testing.T) {
	config := DefaultHealthCheckConfig()
	hc := NewHealthChecker(config)

	// Initially unknown
	if status := hc.GetStatus(); status != HealthStatusUnknown {
		t.Errorf("GetStatus() = %v, want %v", status, HealthStatusUnknown)
	}

	// Perform a check
	ctx := context.Background()
	_ = hc.Check(ctx)

	// Now should be healthy
	if status := hc.GetStatus(); status != HealthStatusHealthy {
		t.Errorf("GetStatus() = %v, want %v", status, HealthStatusHealthy)
	}
}

func TestHealthCheckConstants(t *testing.T) {
	if DefaultHealthCheckInterval != 30*time.Second {
		t.Errorf("DefaultHealthCheckInterval = %v, want 30s", DefaultHealthCheckInterval)
	}

	if DefaultHandshakeTimeout != 2*time.Minute {
		t.Errorf("DefaultHandshakeTimeout = %v, want 2m", DefaultHandshakeTimeout)
	}

	if DefaultGRPCPingTimeout != 10*time.Second {
		t.Errorf("DefaultGRPCPingTimeout = %v, want 10s", DefaultGRPCPingTimeout)
	}

	if DefaultConsecutiveFailures != 3 {
		t.Errorf("DefaultConsecutiveFailures = %v, want 3", DefaultConsecutiveFailures)
	}
}

func TestHealthCheckerRecovery(t *testing.T) {
	config := HealthCheckConfig{
		Interval:            50 * time.Millisecond,
		ConsecutiveFailures: 3,
	}

	hc := NewHealthChecker(config)

	failCount := int32(0)
	hc.SetInterfaceChecker(func() (bool, error) {
		n := atomic.LoadInt32(&failCount)
		atomic.AddInt32(&failCount, 1)
		// Fail first 2 times, then succeed
		return n >= 2, nil
	})

	ctx := context.Background()

	// First check - fail
	result := hc.Check(ctx)
	if result.Status != HealthStatusUnhealthy {
		t.Errorf("First check status = %v, want unhealthy", result.Status)
	}

	// Second check - fail
	result = hc.Check(ctx)
	if result.Status != HealthStatusUnhealthy {
		t.Errorf("Second check status = %v, want unhealthy", result.Status)
	}

	// Third check - succeed (recovery)
	result = hc.Check(ctx)
	if result.Status != HealthStatusHealthy {
		t.Errorf("Third check status = %v, want healthy", result.Status)
	}
}
