//go:build with_naive_outbound && with_quic

// Package hikkari registers the Hikkari outbound: the protocol lives in
// github.com/m1d1x/hikkari-protocol, this adapter builds its two channels from
// sing-box parts.
//
//	stream channel   sing-box's naive outbound (Chromium via cronet), with
//	                 UDP-over-TCP for the fallback
//	datagram channel hikkari-protocol/client.Datagram over sing-box's dialer
//	                 and TLS
package hikkari

import (
	"context"
	"net"
	"time"

	hkclient "github.com/m1d1x/hikkari-protocol/client"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/naive"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.HikkariOutboundOptions](registry, C.TypeHikkari, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	stream   adapter.Outbound
	datagram *hkclient.Datagram
	client   *hkclient.Client
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
		return nil, E.Cause(err, "stream channel")
	}
	o := &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeHikkari, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		stream:  stream,
	}
	udp := common.PtrValueOrDefault(options.UDP)
	clientOptions := hkclient.Options{
		Stream:         stream,
		ConnectTimeout: time.Duration(udp.ConnectTimeout),
		RetryAfter:     time.Duration(udp.RetryAfter),
		Logger:         logger,
	}
	if !udp.Disabled {
		server := options.ServerOptions
		if udp.ServerPort != 0 {
			server.ServerPort = udp.ServerPort
		}
		tlsOptions := *options.TLS
		tlsOptions.ALPN = nil
		tlsConfig, err := tls.NewClient(ctx, logger, options.Server, tlsOptions)
		if err != nil {
			return nil, E.Cause(err, "datagram channel TLS")
		}
		datagramDialer, err := dialer.NewWithOptions(dialer.Options{
			Context:        ctx,
			Options:        options.DialerOptions,
			RemoteIsDomain: options.ServerIsDomain(),
		})
		if err != nil {
			return nil, E.Cause(err, "datagram channel dialer")
		}
		var salamander string
		if udp.Obfs != nil {
			if udp.Obfs.Type != "" && udp.Obfs.Type != "salamander" {
				return nil, E.New("datagram channel: unknown obfs type: ", udp.Obfs.Type)
			}
			if udp.Obfs.Password == "" {
				return nil, E.New("datagram channel: missing obfs password")
			}
			salamander = udp.Obfs.Password
		}
		o.datagram, err = hkclient.NewDatagram(hkclient.DatagramOptions{
			Context:    ctx,
			Dialer:     datagramDialer,
			Server:     server.Build(),
			Password:   options.Password,
			TLS:        tlsConfig,
			Salamander: salamander,
			Logger:     logger,
		})
		if err != nil {
			return nil, E.Cause(err, "datagram channel")
		}
		clientOptions.Datagram = o.datagram
	}
	o.client = hkclient.New(clientOptions)
	return o, nil
}

func (o *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if lifecycle, ok := o.stream.(adapter.Lifecycle); ok {
		if err := lifecycle.Start(stage, scope); err != nil {
			return err
		}
	}
	if stage == adapter.StartStateInitialize && o.datagram != nil {
		scope.Add(o.datagram.Close)
	}
	return nil
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return o.client.DialContext(ctx, network, destination)
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return o.client.ListenPacket(ctx, destination)
}

func (o *Outbound) InterfaceUpdated(ctx context.Context) {
	if updater, ok := o.stream.(adapter.InterfaceUpdateListener); ok {
		updater.InterfaceUpdated(ctx)
	}
	if o.datagram != nil {
		o.datagram.NetworkChanged()
	}
	o.client.NetworkChanged()
}
