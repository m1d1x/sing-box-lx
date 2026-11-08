package option

import "github.com/sagernet/sing/common/json/badoption"

// HikkariOutboundOptions is Hikkari v1 (v1.01, v1.02): one server, one credential, two
// channels. TCP goes over Naive (HTTP/2 CONNECT through Chromium's stack), UDP
// over QUIC datagrams on the same host (the Hysteria2 wire); when the datagram
// channel does not connect, UDP goes over the Naive channel as UDP-over-TCP.
type HikkariOutboundOptions struct {
	DialerOptions
	ServerOptions
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// TLS is shared: server name and trust roots apply to both channels.
	OutboundTLSOptionsContainer
	UDP *HikkariUDPOptions `json:"udp,omitempty"`
}

type HikkariUDPOptions struct {
	// Disabled sends UDP over the Naive channel only.
	Disabled bool `json:"disabled,omitempty"`
	// ServerPort of the datagram channel, server_port when empty.
	ServerPort uint16 `json:"server_port,omitempty"`
	// Obfs wraps the datagram channel (Hysteria2 salamander), off when empty.
	Obfs *Hysteria2Obfs `json:"obfs,omitempty"`
	// ConnectTimeout bounds one attempt of the datagram channel before UDP
	// falls back to the Naive channel; 4s when empty.
	ConnectTimeout badoption.Duration `json:"connect_timeout,omitempty"`
	// RetryAfter is how long UDP stays on the Naive channel after the
	// datagram channel failed; 60s when empty.
	RetryAfter badoption.Duration `json:"retry_after,omitempty"`
	// Dup carries UDP as v1.02 duplicated sessions: by the datagram channel,
	// and by the Naive channel too while a flow looks like a call. The relay
	// must serve it (dup=1 in the link).
	Dup bool `json:"dup,omitempty"`
}
