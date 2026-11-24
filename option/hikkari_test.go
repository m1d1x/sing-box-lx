package option

import (
	"context"
	"testing"

	"github.com/sagernet/sing/common/json"
)

// hikkari 0019: a Hikkari outbound names the further entries of a cascade,
// and they survive a round trip.
func TestHikkariOutboundEntries(t *testing.T) {
	content := `{"server":"203.0.113.1","server_port":443,"password":"k",
		"tls":{"enabled":true,"server_name":"edge.example"},"udp":{"dup":true},
		"entries":[{"server":"198.51.100.7","server_port":8443},{"server":"entry.example","server_port":443}]}`
	var h HikkariOutboundOptions
	if err := json.UnmarshalContext(context.Background(), []byte(content), &h); err != nil {
		t.Fatal(err)
	}
	want := []ServerOptions{{Server: "198.51.100.7", ServerPort: 8443}, {Server: "entry.example", ServerPort: 443}}
	if len(h.Entries) != len(want) || h.Entries[0] != want[0] || h.Entries[1] != want[1] {
		t.Fatalf("entries %+v, want %+v", h.Entries, want)
	}
	if h.Server != "203.0.113.1" || h.ServerPort != 443 || h.UDP == nil || !h.UDP.Dup {
		t.Fatalf("entry 0 %s:%d, udp %+v", h.Server, h.ServerPort, h.UDP)
	}
	back, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	var again HikkariOutboundOptions
	if err := json.UnmarshalContext(context.Background(), back, &again); err != nil || len(again.Entries) != 2 || again.Entries[1] != want[1] {
		t.Fatalf("entries do not survive a round trip: %s, %v", back, err)
	}
	var none HikkariOutboundOptions
	if err := json.UnmarshalContext(context.Background(), []byte(`{"server":"a","server_port":1}`), &none); err != nil || none.Entries != nil {
		t.Fatalf("a config without entries: %+v, %v", none.Entries, err)
	}
}
