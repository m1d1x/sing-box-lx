package dialer

import (
	"context"
	"net"
	"time"
)

// A path can lose some TCP flows to an address and carry others, decided by the
// source port: the SYN goes nowhere and every retransmit of it follows, because
// a retransmit is the same flow. A new attempt is a new source port, so it has a
// fresh chance. It starts only after the attempts before it stayed silent for a
// whole delay, so a path that answers never sees a second SYN.
const flowRetryAttempts = 3

type flowDialResult struct {
	conn net.Conn
	err  error
}

// dialRetryingFlows returns the first connection that opens. An attempt that
// fails fast was answered, so the path is not what lost it, and the failure is
// returned without trying again.
func dialRetryingFlows(ctx context.Context, delay time.Duration, dial func(context.Context) (net.Conn, error)) (net.Conn, error) {
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan flowDialResult, flowRetryAttempts)
	start := func() {
		go func() {
			conn, err := dial(dialCtx)
			results <- flowDialResult{conn, err}
		}()
	}
	start()
	started, finished := 1, 0
	abandon := func() {
		cancel()
		for i := finished; i < started; i++ {
			go func() {
				if result := <-results; result.conn != nil {
					result.conn.Close()
				}
			}()
		}
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	var firstErr error
	for {
		select {
		case result := <-results:
			finished++
			if result.err == nil {
				abandon()
				return result.conn, nil
			}
			if firstErr == nil {
				firstErr = result.err
			}
			if finished == started {
				return nil, firstErr
			}
		case <-timer.C:
			if started < flowRetryAttempts {
				start()
				started++
				timer.Reset(delay)
			}
		case <-ctx.Done():
			abandon()
			return nil, ctx.Err()
		}
	}
}
