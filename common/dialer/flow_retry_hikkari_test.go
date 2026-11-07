package dialer

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type closeCounter struct {
	net.Conn
	closed *atomic.Int32
}

func (c closeCounter) Close() error {
	c.closed.Add(1)
	return nil
}

func TestFlowRetryNewFlowGetsThroughWhenTheFirstIsLost(t *testing.T) {
	var attempts, closed atomic.Int32
	conn, err := dialRetryingFlows(context.Background(), 10*time.Millisecond, func(ctx context.Context) (net.Conn, error) {
		if attempts.Add(1) == 1 {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return closeCounter{closed: &closed}, nil
	})
	if err != nil || conn == nil {
		t.Fatalf("conn = %v, err = %v", conn, err)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("attempts = %d, want 2", got)
	}
}

func TestFlowRetryAnsweringPathSeesOneAttempt(t *testing.T) {
	var attempts, closed atomic.Int32
	_, err := dialRetryingFlows(context.Background(), 20*time.Millisecond, func(context.Context) (net.Conn, error) {
		attempts.Add(1)
		return closeCounter{closed: &closed}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	if got := attempts.Load(); got != 1 {
		t.Fatalf("attempts = %d, want 1", got)
	}
}

func TestFlowRetryFastFailureIsNotRetried(t *testing.T) {
	refused := errors.New("connection refused")
	var attempts atomic.Int32
	_, err := dialRetryingFlows(context.Background(), 20*time.Millisecond, func(context.Context) (net.Conn, error) {
		attempts.Add(1)
		return nil, refused
	})
	if !errors.Is(err, refused) {
		t.Fatalf("err = %v", err)
	}
	time.Sleep(60 * time.Millisecond)
	if got := attempts.Load(); got != 1 {
		t.Fatalf("attempts = %d, want 1", got)
	}
}

func TestFlowRetryStopsAtTheLimitAndReportsFailure(t *testing.T) {
	lost := errors.New("i/o timeout")
	var attempts atomic.Int32
	_, err := dialRetryingFlows(context.Background(), 5*time.Millisecond, func(context.Context) (net.Conn, error) {
		attempts.Add(1)
		time.Sleep(40 * time.Millisecond)
		return nil, lost
	})
	if !errors.Is(err, lost) {
		t.Fatalf("err = %v", err)
	}
	if got := attempts.Load(); got != flowRetryAttempts {
		t.Fatalf("attempts = %d, want %d", got, flowRetryAttempts)
	}
}

func TestFlowRetryClosesTheLoserThatOpenedLate(t *testing.T) {
	var attempts, closed atomic.Int32
	release := make(chan struct{})
	conn, err := dialRetryingFlows(context.Background(), 5*time.Millisecond, func(context.Context) (net.Conn, error) {
		if attempts.Add(1) == 1 {
			<-release
		}
		return closeCounter{closed: &closed}, nil
	})
	if err != nil || conn == nil {
		t.Fatalf("conn = %v, err = %v", conn, err)
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for closed.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if closed.Load() != 1 {
		t.Fatalf("late loser closed %d times", closed.Load())
	}
}
