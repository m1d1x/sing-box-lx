//go:build with_naive_outbound && with_quic

package include

import (
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/protocol/hikkari"
)

func registerHikkariOutbound(registry *outbound.Registry) {
	hikkari.RegisterOutbound(registry)
}
