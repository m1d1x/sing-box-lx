//go:build with_naive_outbound && with_quic

// Package hikkari is the client of Hikkari v1.01: one outbound, two channels.
//
//	TCP ─► Naive channel: HTTP/2 CONNECT through Chromium's network stack
//	UDP ─► datagram channel: QUIC DATAGRAM on the same host (Hysteria2 wire)
//	    └► when that does not connect: UDP-over-TCP inside the Naive channel
//
// The two channels share the server, the credential and the TLS trust. They
// keep their own health: a dead datagram channel never touches TCP, and UDP
// tries the datagram channel again after retry_after.
package hikkari

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/naive"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	defaultConnectTimeout = 4 * time.Second
	defaultRetryAfter     = 60 * time.Second
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.HikkariOutboundOptions](registry, C.TypeHikkari, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger         logger.ContextLogger
	stream         adapter.Outbound
	datagram       adapter.Outbound
	connectTimeout time.Duration
	retryAfter     time.Duration

	access   sync.Mutex
	badUntil time.Time
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.HikkariOutboundOptions) (adapter.Outbound, error) {
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	if options.Password == "" {
		return nil, E.New("missing password")
	}
	username := options.Username
	if username == "" {
		username = "hikkari"
	}
	stream, err := naive.NewOutbound(ctx, router, logger, tag, option.NaiveOutboundOptions{
		DialerOptions:               options.DialerOptions,
		ServerOptions:               options.ServerOptions,
		Username:                    username,
		Password:                    options.Password,
		UDPOverTCP:                  &option.UDPOverTCPOptions{Enabled: true, Version: 2},
		OutboundTLSOptionsContainer: options.OutboundTLSOptionsContainer,
	})
	if err != nil {
		return nil, E.Cause(err, "naive channel")
	}
	o := &Outbound{
		Adapter:        outbound.NewAdapterWithDialerOptions(C.TypeHikkari, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		logger:         logger,
		stream:         stream,
		connectTimeout: defaultConnectTimeout,
		retryAfter:     defaultRetryAfter,
	}
	udp := common.PtrValueOrDefault(options.UDP)
	if udp.ConnectTimeout > 0 {
		o.connectTimeout = time.Duration(udp.ConnectTimeout)
	}
	if udp.RetryAfter > 0 {
		o.retryAfter = time.Duration(udp.RetryAfter)
	}
	if !udp.Disabled {
		server := options.ServerOptions
		if udp.ServerPort != 0 {
			server.ServerPort = udp.ServerPort
		}
		tls := *options.TLS
		tls.ALPN = nil
		o.datagram, err = hysteria2.NewOutbound(ctx, router, logger, tag, option.Hysteria2OutboundOptions{
			DialerOptions:               options.DialerOptions,
			ServerOptions:               server,
			Obfs:                        udp.Obfs,
			Password:                    options.Password,
			Network:                     option.NetworkList(N.NetworkUDP),
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &tls},
		})
		if err != nil {
			return nil, E.Cause(err, "datagram channel")
		}
	}
	return o, nil
}

func (o *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	for _, channel := range []adapter.Outbound{o.stream, o.datagram} {
		if lifecycle, ok := channel.(adapter.Lifecycle); ok {
			if err := lifecycle.Start(stage, scope); err != nil {
				return err
			}
		}
	}
	return nil
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return o.stream.DialContext(ctx, network, destination)
	case N.NetworkUDP:
		if o.datagramUp() {
			conn, err := o.tryDatagram(ctx, func(ctx context.Context) (net.Conn, error) {
				return o.datagram.DialContext(ctx, network, destination)
			})
			if err == nil {
				return conn, nil
			}
		}
		return o.stream.DialContext(ctx, network, destination)
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if o.datagramUp() {
		var packetConn net.PacketConn
		_, err := o.tryDatagram(ctx, func(ctx context.Context) (net.Conn, error) {
			var err error
			packetConn, err = o.datagram.ListenPacket(ctx, destination)
			return nil, err
		})
		if err == nil {
			return packetConn, nil
		}
	}
	return o.stream.ListenPacket(ctx, destination)
}

// datagramUp reports whether UDP should try the datagram channel now.
func (o *Outbound) datagramUp() bool {
	if o.datagram == nil {
		return false
	}
	o.access.Lock()
	defer o.access.Unlock()
	return time.Now().After(o.badUntil)
}

// tryDatagram runs one attempt on the datagram channel within connect_timeout.
// A failure keeps UDP on the Naive channel for retry_after; the caller's own
// cancellation is not the channel's fault.
func (o *Outbound) tryDatagram(ctx context.Context, attempt func(context.Context) (net.Conn, error)) (net.Conn, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, o.connectTimeout)
	defer cancel()
	conn, err := attempt(attemptCtx)
	if err == nil || ctx.Err() != nil {
		return conn, err
	}
	o.access.Lock()
	first := time.Now().After(o.badUntil)
	o.badUntil = time.Now().Add(o.retryAfter)
	o.access.Unlock()
	if first {
		o.logger.WarnContext(ctx, "datagram channel failed, UDP goes over the naive channel for ", o.retryAfter, ": ", err)
	}
	return nil, err
}

func (o *Outbound) InterfaceUpdated(ctx context.Context) {
	for _, channel := range []adapter.Outbound{o.stream, o.datagram} {
		if updater, ok := channel.(adapter.InterfaceUpdateListener); ok {
			updater.InterfaceUpdated(ctx)
		}
	}
	// A new network may pass what the old one blocked.
	o.access.Lock()
	o.badUntil = time.Time{}
	o.access.Unlock()
}
