// Machine Tunnel Fork - Reconnect Logic
// This file provides exponential backoff reconnection for the Machine Tunnel.

package tunnel

import (
	"context"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// DefaultInitialBackoff is the initial reconnect delay
	DefaultInitialBackoff = 1 * time.Second

	// DefaultMaxBackoff is the maximum reconnect delay
	DefaultMaxBackoff = 5 * time.Minute

	// DefaultBackoffMultiplier is the multiplier for exponential backoff
	DefaultBackoffMultiplier = 2.0

	// DefaultMaxRetries is the maximum number of retries (0 = infinite)
	DefaultMaxRetries = 0
)

// ReconnectConfig configures the reconnection behavior
type ReconnectConfig struct {
	// InitialBackoff is the initial delay before first reconnect attempt
	InitialBackoff time.Duration

	// MaxBackoff is the maximum delay between reconnect attempts
	MaxBackoff time.Duration

	// Multiplier is the factor by which backoff increases after each failure
	Multiplier float64

	// MaxRetries is the maximum number of reconnect attempts (0 = infinite)
	MaxRetries int

	// Jitter adds randomness to backoff to prevent thundering herd
	Jitter bool
}

// DefaultReconnectConfig returns the default reconnection configuration
func DefaultReconnectConfig() ReconnectConfig {
	return ReconnectConfig{
		InitialBackoff: DefaultInitialBackoff,
		MaxBackoff:     DefaultMaxBackoff,
		Multiplier:     DefaultBackoffMultiplier,
		MaxRetries:     DefaultMaxRetries,
		Jitter:         true,
	}
}

// ReconnectManager manages automatic reconnection with exponential backoff
type ReconnectManager struct {
	mu sync.Mutex

	config ReconnectConfig

	// currentBackoff is the current backoff duration
	currentBackoff time.Duration

	// retryCount is the number of reconnect attempts
	retryCount int

	// connectFunc is the function called to establish connection
	connectFunc func(ctx context.Context) error

	// disconnectCh signals when a disconnect occurs
	disconnectCh chan struct{}

	// stopCh signals when to stop the reconnect loop
	stopCh chan struct{}

	// running indicates if the reconnect loop is running
	running bool

	// lastError stores the last connection error
	lastError error

	// lastAttempt is the time of the last connection attempt
	lastAttempt time.Time
}

// NewReconnectManager creates a new reconnect manager
func NewReconnectManager(config ReconnectConfig, connectFunc func(ctx context.Context) error) *ReconnectManager {
	if config.InitialBackoff == 0 {
		config.InitialBackoff = DefaultInitialBackoff
	}
	if config.MaxBackoff == 0 {
		config.MaxBackoff = DefaultMaxBackoff
	}
	if config.Multiplier == 0 {
		config.Multiplier = DefaultBackoffMultiplier
	}

	return &ReconnectManager{
		config:         config,
		currentBackoff: config.InitialBackoff,
		connectFunc:    connectFunc,
		disconnectCh:   make(chan struct{}, 1),
		stopCh:         make(chan struct{}),
	}
}

// Start begins the reconnect loop
func (r *ReconnectManager) Start(ctx context.Context) error {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return fmt.Errorf("reconnect manager already running")
	}
	r.running = true
	r.stopCh = make(chan struct{})
	r.mu.Unlock()

	go r.reconnectLoop(ctx)
	return nil
}

// Stop stops the reconnect loop
func (r *ReconnectManager) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.running {
		return
	}

	close(r.stopCh)
	r.running = false
}

// NotifyDisconnect signals that a disconnect has occurred
func (r *ReconnectManager) NotifyDisconnect() {
	select {
	case r.disconnectCh <- struct{}{}:
	default:
		// Channel already has a notification
	}
}

// ResetBackoff resets the backoff to initial value
func (r *ReconnectManager) ResetBackoff() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.currentBackoff = r.config.InitialBackoff
	r.retryCount = 0
	r.lastError = nil
}

// GetStats returns current reconnect statistics
func (r *ReconnectManager) GetStats() ReconnectStats {
	r.mu.Lock()
	defer r.mu.Unlock()

	return ReconnectStats{
		RetryCount:     r.retryCount,
		CurrentBackoff: r.currentBackoff,
		LastError:      r.lastError,
		LastAttempt:    r.lastAttempt,
		IsRunning:      r.running,
	}
}

// ReconnectStats contains statistics about reconnection attempts
type ReconnectStats struct {
	RetryCount     int
	CurrentBackoff time.Duration
	LastError      error
	LastAttempt    time.Time
	IsRunning      bool
}

// reconnectLoop is the main reconnection loop
func (r *ReconnectManager) reconnectLoop(ctx context.Context) {
	log.Info("Reconnect manager started")

	for {
		select {
		case <-ctx.Done():
			log.Info("Reconnect manager stopped (context cancelled)")
			return
		case <-r.stopCh:
			log.Info("Reconnect manager stopped")
			return
		default:
		}

		// Attempt connection
		r.mu.Lock()
		r.lastAttempt = time.Now()
		r.mu.Unlock()

		err := r.connectFunc(ctx)
		if err == nil {
			// Success - reset backoff
			r.ResetBackoff()
			log.Info("Connection established, waiting for disconnect signal")

			// Wait for disconnect
			select {
			case <-ctx.Done():
				return
			case <-r.stopCh:
				return
			case <-r.disconnectCh:
				log.Info("Disconnect detected, initiating reconnect")
				continue
			}
		}

		// Connection failed
		r.mu.Lock()
		r.lastError = err
		r.retryCount++
		backoff := r.currentBackoff
		r.mu.Unlock()

		log.WithFields(log.Fields{
			"error":      err,
			"backoff":    backoff,
			"retry":      r.retryCount,
			"maxRetries": r.config.MaxRetries,
		}).Warn("Connection failed, scheduling reconnect")

		// Check max retries
		if r.config.MaxRetries > 0 && r.retryCount >= r.config.MaxRetries {
			log.Errorf("Max retries (%d) exceeded, stopping reconnect manager", r.config.MaxRetries)
			r.mu.Lock()
			r.running = false
			r.mu.Unlock()
			return
		}

		// Wait with backoff
		select {
		case <-ctx.Done():
			return
		case <-r.stopCh:
			return
		case <-time.After(backoff):
		}

		// Increase backoff
		r.mu.Lock()
		r.currentBackoff = r.calculateNextBackoff(r.currentBackoff)
		r.mu.Unlock()
	}
}

// calculateNextBackoff calculates the next backoff duration
func (r *ReconnectManager) calculateNextBackoff(current time.Duration) time.Duration {
	next := time.Duration(float64(current) * r.config.Multiplier)

	if next > r.config.MaxBackoff {
		next = r.config.MaxBackoff
	}

	return next
}

// ConnectWithRetry attempts connection with automatic retry on failure
// This is a blocking function that returns when connected or max retries exceeded
func (r *ReconnectManager) ConnectWithRetry(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		r.mu.Lock()
		r.lastAttempt = time.Now()
		r.mu.Unlock()

		err := r.connectFunc(ctx)
		if err == nil {
			r.ResetBackoff()
			return nil
		}

		r.mu.Lock()
		r.lastError = err
		r.retryCount++
		backoff := r.currentBackoff
		r.mu.Unlock()

		log.WithFields(log.Fields{
			"error":   err,
			"backoff": backoff,
			"retry":   r.retryCount,
		}).Warn("Connection attempt failed")

		if r.config.MaxRetries > 0 && r.retryCount >= r.config.MaxRetries {
			return fmt.Errorf("max retries (%d) exceeded: %w", r.config.MaxRetries, err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}

		r.mu.Lock()
		r.currentBackoff = r.calculateNextBackoff(r.currentBackoff)
		r.mu.Unlock()
	}
}
