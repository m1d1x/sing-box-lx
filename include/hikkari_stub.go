//go:build !(with_naive_outbound && with_quic)

package include

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func registerHikkariOutbound(registry *outbound.Registry) {
	outbound.Register[option.HikkariOutboundOptions](registry, C.TypeHikkari, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.HikkariOutboundOptions) (adapter.Outbound, error) {
		return nil, E.New(`hikkari outbound is not included in this build, rebuild with -tags with_naive_outbound,with_quic`)
	})
}
