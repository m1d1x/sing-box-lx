//go:build with_naive_outbound && with_quic

package hikkari

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	hkclient "github.com/m1d1x/hikkari-protocol/client"
	"github.com/m1d1x/hikkari-protocol/observe"
	"github.com/sagernet/sing-box/log"
)

// PeriodEvery is how often the outbound writes what its sessions saw (Hikkari
// v1.04 observability, hikkari-protocol spec/v1.md).
const PeriodEvery = 10 * time.Minute

// periodPrefix starts the line; the app tells these lines by it and the hub
// reads them from testers' logs.
const periodPrefix = "hikkari period s="

// periods writes the outbound's book to the log every PeriodEvery and once
// more when the outbound closes. A period holds counts and distributions
// only: no address, destination or key.
type periods struct {
	book   *observe.Book
	logger log.ContextLogger
	ctx    context.Context
	stop   context.CancelFunc
	once   sync.Once
	mu     sync.Mutex
	since  time.Time
}

func newPeriods(ctx context.Context, logger log.ContextLogger) *periods {
	ctx, stop := context.WithCancel(ctx)
	return &periods{book: observe.NewBook(), logger: logger, ctx: ctx, stop: stop, since: time.Now()}
}

// run writes a period every PeriodEvery until close.
func (p *periods) run() {
	t := time.NewTicker(PeriodEvery)
	defer t.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-t.C:
			p.write()
		}
	}
}

// close stops the loop and writes the last period.
func (p *periods) close() error {
	p.once.Do(func() {
		p.stop()
		p.write()
	})
	return nil
}

func (p *periods) write() {
	p.mu.Lock()
	defer p.mu.Unlock()
	period := p.book.Take()[hkclient.Group]
	seconds := int64(time.Since(p.since).Seconds())
	p.since = time.Now()
	if period == nil {
		return
	}
	raw, err := json.Marshal(period)
	if err != nil {
		return
	}
	p.logger.Warn(periodPrefix, seconds, " ", string(raw))
}
