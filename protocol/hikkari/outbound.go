//go:build with_naive_outbound && with_quic

// Package hikkari registers the Hikkari outbound: the protocol lives in
// github.com/m1d1x/hikkari-protocol, this adapter builds its two channels from
// sing-box parts.
//
//	stream channel   sing-box's naive outbound (Chromium via cronet), with
//	                 UDP-over-TCP for the fallback
//	datagram channel hikkari-protocol/client.Datagram over sing-box's dialer
//	                 and TLS
//	voice channel    with udp.dup, a second client.Datagram to the same relay:
//	                 a QUIC connection of its own for calls' voice (v1.03)
//
// With entries (v1.07), the outbound builds the three channels once per entry
// of the cascade; the protocol client pings every entry and leaves a silent
// one by itself.
//
// What the outbound's sessions saw goes to the log as periods (v1.04,
// period.go).
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
	paths   []entryPath
	client  *hkclient.Client
	periods *periods
	stop    context.CancelFunc
}

// entryPath is one entry's channels.
type entryPath struct {
	stream   adapter.Outbound
	datagram *hkclient.Datagram
	voice    *hkclient.Datagram
}

func (p entryPath) path() hkclient.Path {
	path := hkclient.Path{Stream: p.stream}
	if p.datagram != nil {
		path.Datagram = p.datagram
	}
	if p.voice != nil {
		path.VoiceDatagram = p.voice
	}
	return path
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.HikkariOutboundOptions) (adapter.Outbound, error) {
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	if options.Password == "" {
		return nil, E.New("missing password")
	}
	for i, entry := range options.Entries {
		if entry.Server == "" || entry.ServerPort == 0 {
			return nil, E.New("entry ", i+1, ": missing server or server_port")
		}
	}
	udp := common.PtrValueOrDefault(options.UDP)
	o := &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeHikkari, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		periods: newPeriods(ctx, logger),
	}
	entries := append([]option.ServerOptions{options.ServerOptions}, options.Entries...)
	for i, entry := range entries {
		// Entry 0 may name the datagram channel's own port; every further
		// entry forwards both channels on its one port.
		udpPort := entry.ServerPort
		if i == 0 && udp.ServerPort != 0 {
			udpPort = udp.ServerPort
		}
		p, err := o.newPath(ctx, router, logger, tag, options, udp, entry, udpPort)
		if err != nil {
			if len(entries) > 1 {
				return nil, E.Cause(err, "entry ", i)
			}
			return nil, err
		}
		o.paths = append(o.paths, p)
	}
	clientOptions := hkclient.Options{
		ConnectTimeout: time.Duration(udp.ConnectTimeout),
		RetryAfter:     time.Duration(udp.RetryAfter),
		Dup:            udp.Dup && !udp.Disabled,
		Logger:         logger,
		Book:           o.periods.book,
	}
	first := o.paths[0].path()
	clientOptions.Stream, clientOptions.Datagram, clientOptions.VoiceDatagram = first.Stream, first.Datagram, first.VoiceDatagram
	for _, p := range o.paths[1:] {
		clientOptions.Paths = append(clientOptions.Paths, p.path())
	}
	if len(o.paths) > 1 {
		// The entries' probes live as long as the outbound.
		clientOptions.Context, o.stop = context.WithCancel(ctx)
	}
	o.client = hkclient.New(clientOptions)
	return o, nil
}

// newPath builds one entry's channels: Naive to entry, and with UDP the
// datagram channel (and with dup the voice channel) to entry's host on
// udpPort. Key, TLS and relay are the same for every entry.
func (o *Outbound) newPath(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string,
	options option.HikkariOutboundOptions, udp option.HikkariUDPOptions, entry option.ServerOptions, udpPort uint16,
) (entryPath, error) {
	var p entryPath
	username := options.Username
	if username == "" {
		username = "hikkari"
	}
	stream, err := naive.NewOutbound(ctx, router, logger, tag, option.NaiveOutboundOptions{
		DialerOptions:               options.DialerOptions,
		ServerOptions:               entry,
		Username:                    username,
		Password:                    options.Password,
		UDPOverTCP:                  &option.UDPOverTCPOptions{Enabled: true, Version: 2},
		OutboundTLSOptionsContainer: options.OutboundTLSOptionsContainer,
	})
	if err != nil {
		return p, E.Cause(err, "stream channel")
	}
	p.stream = stream
	if udp.Disabled {
		return p, nil
	}
	server := entry
	server.ServerPort = udpPort
	tlsOptions := *options.TLS
	tlsOptions.ALPN = nil
	tlsConfig, err := tls.NewClient(ctx, logger, entry.Server, tlsOptions)
	if err != nil {
		return p, E.Cause(err, "datagram channel TLS")
	}
	datagramDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:        ctx,
		Options:        options.DialerOptions,
		RemoteIsDomain: entry.ServerIsDomain(),
	})
	if err != nil {
		return p, E.Cause(err, "datagram channel dialer")
	}
	var salamander string
	if udp.Obfs != nil {
		if udp.Obfs.Type != "" && udp.Obfs.Type != "salamander" {
			return p, E.New("datagram channel: unknown obfs type: ", udp.Obfs.Type)
		}
		if udp.Obfs.Password == "" {
			return p, E.New("datagram channel: missing obfs password")
		}
		salamander = udp.Obfs.Password
	}
	datagramOptions := hkclient.DatagramOptions{
		Context:    ctx,
		Dialer:     datagramDialer,
		Server:     server.Build(),
		Password:   options.Password,
		TLS:        tlsConfig,
		Salamander: salamander,
		Logger:     logger,
		Book:       o.periods.book,
		Name:       "datagram",
	}
	p.datagram, err = hkclient.NewDatagram(datagramOptions)
	if err != nil {
		return p, E.Cause(err, "datagram channel")
	}
	if !udp.Dup {
		return p, nil
	}
	// v1.03: a call's voice gets a QUIC connection of its own, so it never
	// queues behind the video and bulk of the first one. The client uses it
	// only with a relay that keeps lanes. Its own TLS config: the datagram
	// client sets the config's ALPN.
	voiceTLS, err := tls.NewClient(ctx, logger, entry.Server, tlsOptions)
	if err != nil {
		return p, E.Cause(err, "voice channel TLS")
	}
	voiceOptions := datagramOptions
	voiceOptions.TLS = voiceTLS
	voiceOptions.Name = "voice"
	p.voice, err = hkclient.NewDatagram(voiceOptions)
	if err != nil {
		return p, E.Cause(err, "voice channel")
	}
	return p, nil
}

func (o *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	for _, p := range o.paths {
		if lifecycle, ok := p.stream.(adapter.Lifecycle); ok {
			if err := lifecycle.Start(stage, scope); err != nil {
				return err
			}
		}
	}
	if stage == adapter.StartStateInitialize {
		// Added first, so it runs after the channels closed: their last
		// counts are in the last period.
		scope.Add(o.periods.close)
		if o.stop != nil {
			scope.Add(func() error { o.stop(); return nil })
		}
		for _, p := range o.paths {
			if p.datagram != nil {
				scope.Add(p.datagram.Close)
			}
			if p.voice != nil {
				scope.Add(p.voice.Close)
			}
		}
	}
	if stage == adapter.StartStateStart {
		go o.periods.run()
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
	for _, p := range o.paths {
		if updater, ok := p.stream.(adapter.InterfaceUpdateListener); ok {
			updater.InterfaceUpdated(ctx)
		}
		if p.datagram != nil {
			p.datagram.NetworkChanged()
		}
		if p.voice != nil {
			p.voice.NetworkChanged()
		}
	}
	o.client.NetworkChanged()
}
