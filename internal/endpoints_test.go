package internal

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"

	"github.com/soerenschneider/vault-unsealer/v2/internal/config"
	"github.com/soerenschneider/vault-unsealer/v2/internal/unsealing"
)

type fakeResolver struct {
	records []*net.SRV
	err     error
	names   []string
}

func (r *fakeResolver) LookupSRV(_ context.Context, service, proto, name string) (string, []*net.SRV, error) {
	r.names = append(r.names, service+proto+name)
	return name, r.records, r.err
}

func TestSrvEndpoints(t *testing.T) {
	tests := []struct {
		name    string
		scheme  string
		records []*net.SRV
		err     error
		want    []string
		wantErr bool
	}{
		{
			name:   "sorted, without trailing dot and duplicates",
			scheme: "https",
			records: []*net.SRV{
				{Target: "vault-2.example.com.", Port: 8200, Priority: 10},
				{Target: "vault-1.example.com.", Port: 8200, Priority: 20},
				{Target: "vault-2.example.com.", Port: 8200, Priority: 30},
			},
			want: []string{"https://vault-1.example.com:8200", "https://vault-2.example.com:8200"},
		},
		{
			name:    "http scheme and custom port",
			scheme:  "http",
			records: []*net.SRV{{Target: "vault.example.com.", Port: 8201}},
			want:    []string{"http://vault.example.com:8201"},
		},
		{
			name:    "lookup fails",
			scheme:  "https",
			err:     errors.New("no such host"),
			wantErr: true,
		},
		{
			name:    "service explicitly unavailable",
			scheme:  "https",
			records: []*net.SRV{{Target: ".", Port: 0}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := &fakeResolver{records: tt.records, err: tt.err}
			e := &srvEndpoints{record: "_vault._tcp.example.com", scheme: tt.scheme, resolver: resolver}
			got, err := e.Endpoints(context.Background())
			if (err != nil) != tt.wantErr {
				t.Fatalf("Endpoints() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("Endpoints() = %v, want %v", got, tt.want)
			}
			// the record is looked up verbatim
			if !slices.Equal(resolver.names, []string{"_vault._tcp.example.com"}) {
				t.Fatalf("unexpected lookups %v", resolver.names)
			}
		})
	}
}

func TestNewEndpointDiscovery(t *testing.T) {
	if _, ok := newEndpointDiscovery(config.ClusterConfig{Endpoints: []string{"http://a"}}).(staticEndpoints); !ok {
		t.Fatal("expected static endpoints")
	}
	d, ok := newEndpointDiscovery(config.ClusterConfig{EndpointsSrv: &config.SrvConfig{Record: "_vault._tcp.example.com"}}).(*srvEndpoints)
	if !ok {
		t.Fatal("expected srv endpoints")
	}
	if d.scheme != "https" {
		t.Fatalf("expected default scheme https, got %q", d.scheme)
	}
}

func TestUnsealAgent_DiscoversEndpoints(t *testing.T) {
	client := &fakeVaultClient{sealed: false}
	conf := config.ClusterConfig{EndpointsSrv: &config.SrvConfig{Record: "_vault._tcp.discovery"}}
	agent, err := NewUnsealAgent("discovery", conf, client, []unsealing.UnsealKeyRetriever{&flakyRetriever{}})
	if err != nil {
		t.Fatal(err)
	}
	resolver := &fakeResolver{records: []*net.SRV{
		{Target: "a.discovery.", Port: 8200},
		{Target: "b.discovery.", Port: 8200},
	}}
	agent.discovery.(*srvEndpoints).resolver = resolver
	ctx := context.Background()

	agent.conditionallyUnsealInstances(ctx)
	if got := metricValue(t, Instances.WithLabelValues("discovery")); got != 2 {
		t.Fatalf("expected 2 instances, got %f", got)
	}
	if got := metricValue(t, UnsealedStatus.WithLabelValues("https://b.discovery:8200")); got != 1 {
		t.Fatalf("expected b to be checked, got %f", got)
	}

	// a failing lookup keeps the previously known instances
	resolver.err = errors.New("dns down")
	errorsBefore := metricValue(t, EndpointDiscoveryErrors.WithLabelValues("discovery"))
	if got := agent.discoverEndpoints(ctx); len(got) != 2 {
		t.Fatalf("expected previously known instances, got %v", got)
	}
	if got := metricValue(t, EndpointDiscoveryErrors.WithLabelValues("discovery")) - errorsBefore; got != 1 {
		t.Fatalf("expected 1 discovery error, got %f", got)
	}

	// removed instances are no longer checked and their metrics are deleted
	resolver.err = nil
	resolver.records = resolver.records[:1]
	agent.conditionallyUnsealInstances(ctx)
	if got := metricValue(t, Instances.WithLabelValues("discovery")); got != 1 {
		t.Fatalf("expected 1 instance, got %f", got)
	}
	// Delete* returns false if the series doesn't exist (anymore)
	if UnsealedStatus.DeleteLabelValues("https://b.discovery:8200") || LastCheck.DeleteLabelValues("https://b.discovery:8200") {
		t.Fatal("expected metrics of removed instance to be deleted")
	}
	if got := metricValue(t, UnsealedStatus.WithLabelValues("https://a.discovery:8200")); got != 1 {
		t.Fatalf("expected remaining instance to be checked, got %f", got)
	}
}
