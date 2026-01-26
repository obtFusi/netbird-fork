package tunnel

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestDefaultReconnectConfig(t *testing.T) {
	config := DefaultReconnectConfig()

	if config.InitialBackoff != DefaultInitialBackoff {
		t.Errorf("InitialBackoff = %v, want %v", config.InitialBackoff, DefaultInitialBackoff)
	}

	if config.MaxBackoff != DefaultMaxBackoff {
		t.Errorf("MaxBackoff = %v, want %v", config.MaxBackoff, DefaultMaxBackoff)
	}

	if config.Multiplier != DefaultBackoffMultiplier {
		t.Errorf("Multiplier = %v, want %v", config.Multiplier, DefaultBackoffMultiplier)
	}

	if config.MaxRetries != DefaultMaxRetries {
		t.Errorf("MaxRetries = %v, want %v", config.MaxRetries, DefaultMaxRetries)
	}
}

func TestNewReconnectManager(t *testing.T) {
	connectFunc := func(ctx context.Context) error {
		return nil
	}

	tests := []struct {
		name   string
		config ReconnectConfig
	}{
		{
			name:   "default config",
			config: DefaultReconnectConfig(),
		},
		{
			name: "zero values get defaults",
			config: ReconnectConfig{
				InitialBackoff: 0,
				MaxBackoff:     0,
				Multiplier:     0,
			},
		},
		{
			name: "custom config",
			config: ReconnectConfig{
				InitialBackoff: 2 * time.Second,
				MaxBackoff:     10 * time.Minute,
				Multiplier:     3.0,
				MaxRetries:     5,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := NewReconnectManager(tt.config, connectFunc)
			if rm == nil {
				t.Error("NewReconnectManager returned nil")
			}
		})
	}
}

func TestReconnectManagerStartStop(t *testing.T) {
	connectCalled := int32(0)
	connectFunc := func(ctx context.Context) error {
		atomic.AddInt32(&connectCalled, 1)
		// Simulate connection success
		return nil
	}

	rm := NewReconnectManager(DefaultReconnectConfig(), connectFunc)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start
	if err := rm.Start(ctx); err != nil {
		t.Errorf("Start() error = %v", err)
	}

	// Wait a bit for the first connection attempt
	time.Sleep(100 * time.Millisecond)

	// Should be running
	stats := rm.GetStats()
	if !stats.IsRunning {
		t.Error("Expected manager to be running")
	}

	// Starting again should fail
	if err := rm.Start(ctx); err == nil {
		t.Error("Start() should fail when already running")
	}

	// Stop
	rm.Stop()

	time.Sleep(50 * time.Millisecond)

	// Should not be running
	stats = rm.GetStats()
	if stats.IsRunning {
		t.Error("Expected manager to be stopped")
	}
}

func TestReconnectManagerBackoff(t *testing.T) {
	config := ReconnectConfig{
		InitialBackoff: 100 * time.Millisecond,
		MaxBackoff:     1 * time.Second,
		Multiplier:     2.0,
		MaxRetries:     3,
	}

	attempts := int32(0)
	connectFunc := func(ctx context.Context) error {
		atomic.AddInt32(&attempts, 1)
		return errors.New("connection failed")
	}

	rm := NewReconnectManager(config, connectFunc)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Use ConnectWithRetry for controlled testing
	err := rm.ConnectWithRetry(ctx)

	if err == nil {
		t.Error("Expected error after max retries")
	}

	if atomic.LoadInt32(&attempts) != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}
}

func TestReconnectManagerResetBackoff(t *testing.T) {
	config := ReconnectConfig{
		InitialBackoff: 100 * time.Millisecond,
		MaxBackoff:     1 * time.Second,
		Multiplier:     2.0,
	}

	rm := NewReconnectManager(config, func(ctx context.Context) error {
		return nil
	})

	// Simulate some failures
	rm.mu.Lock()
	rm.currentBackoff = 500 * time.Millisecond
	rm.retryCount = 5
	rm.lastError = errors.New("test error")
	rm.mu.Unlock()

	// Reset
	rm.ResetBackoff()

	stats := rm.GetStats()
	if stats.RetryCount != 0 {
		t.Errorf("RetryCount = %d, want 0", stats.RetryCount)
	}
	if stats.CurrentBackoff != config.InitialBackoff {
		t.Errorf("CurrentBackoff = %v, want %v", stats.CurrentBackoff, config.InitialBackoff)
	}
	if stats.LastError != nil {
		t.Errorf("LastError = %v, want nil", stats.LastError)
	}
}

func TestReconnectManagerNotifyDisconnect(t *testing.T) {
	rm := NewReconnectManager(DefaultReconnectConfig(), func(ctx context.Context) error {
		return nil
	})

	// Multiple notifications should not block
	for i := 0; i < 10; i++ {
		rm.NotifyDisconnect()
	}

	// Drain channel
	select {
	case <-rm.disconnectCh:
		// OK
	default:
		t.Error("Expected notification in channel")
	}
}

func TestCalculateNextBackoff(t *testing.T) {
	config := ReconnectConfig{
		InitialBackoff: 1 * time.Second,
		MaxBackoff:     10 * time.Second,
		Multiplier:     2.0,
	}

	rm := NewReconnectManager(config, func(ctx context.Context) error {
		return nil
	})

	tests := []struct {
		current  time.Duration
		expected time.Duration
	}{
		{1 * time.Second, 2 * time.Second},
		{2 * time.Second, 4 * time.Second},
		{4 * time.Second, 8 * time.Second},
		{8 * time.Second, 10 * time.Second}, // capped at MaxBackoff
		{10 * time.Second, 10 * time.Second}, // stays at MaxBackoff
	}

	for _, tt := range tests {
		t.Run(tt.current.String(), func(t *testing.T) {
			next := rm.calculateNextBackoff(tt.current)
			if next != tt.expected {
				t.Errorf("calculateNextBackoff(%v) = %v, want %v", tt.current, next, tt.expected)
			}
		})
	}
}

func TestConnectWithRetrySuccess(t *testing.T) {
	attempts := int32(0)
	connectFunc := func(ctx context.Context) error {
		n := atomic.AddInt32(&attempts, 1)
		if n < 3 {
			return errors.New("temporary failure")
		}
		return nil // Success on 3rd attempt
	}

	config := ReconnectConfig{
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     100 * time.Millisecond,
		Multiplier:     2.0,
		MaxRetries:     5,
	}

	rm := NewReconnectManager(config, connectFunc)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := rm.ConnectWithRetry(ctx)

	if err != nil {
		t.Errorf("ConnectWithRetry() error = %v", err)
	}

	if atomic.LoadInt32(&attempts) != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}

	stats := rm.GetStats()
	if stats.RetryCount != 0 {
		t.Error("RetryCount should be reset after success")
	}
}

func TestConnectWithRetryContextCancel(t *testing.T) {
	connectFunc := func(ctx context.Context) error {
		return errors.New("always fail")
	}

	config := ReconnectConfig{
		InitialBackoff: 1 * time.Second, // Long backoff
		MaxBackoff:     5 * time.Second,
		Multiplier:     2.0,
		MaxRetries:     0, // Infinite
	}

	rm := NewReconnectManager(config, connectFunc)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := rm.ConnectWithRetry(ctx)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Expected context.DeadlineExceeded, got %v", err)
	}
}

func TestReconnectConstants(t *testing.T) {
	if DefaultInitialBackoff != 1*time.Second {
		t.Errorf("DefaultInitialBackoff = %v, want 1s", DefaultInitialBackoff)
	}

	if DefaultMaxBackoff != 5*time.Minute {
		t.Errorf("DefaultMaxBackoff = %v, want 5m", DefaultMaxBackoff)
	}

	if DefaultBackoffMultiplier != 2.0 {
		t.Errorf("DefaultBackoffMultiplier = %v, want 2.0", DefaultBackoffMultiplier)
	}

	if DefaultMaxRetries != 0 {
		t.Errorf("DefaultMaxRetries = %v, want 0", DefaultMaxRetries)
	}
}
