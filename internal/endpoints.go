package internal

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/soerenschneider/vault-unsealer/v2/internal/config"
)

const srvLookupTimeout = 5 * time.Second

// endpointDiscovery returns the instances of a cluster.
type endpointDiscovery interface {
	Endpoints(ctx context.Context) ([]string, error)
}

func newEndpointDiscovery(conf config.ClusterConfig) endpointDiscovery {
	if conf.EndpointsSrv != nil {
		return &srvEndpoints{
			record:   conf.EndpointsSrv.Record,
			scheme:   conf.EndpointsSrv.SchemeOrDefault(),
			resolver: net.DefaultResolver,
		}
	}
	return staticEndpoints(conf.Endpoints)
}

// staticEndpoints is a fixed list of instances.
type staticEndpoints []string

func (e staticEndpoints) Endpoints(_ context.Context) ([]string, error) {
	return e, nil
}

type srvResolver interface {
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
}

// srvEndpoints discovers instances via a DNS SRV record, e.g. "_vault._tcp.example.com".
type srvEndpoints struct {
	record   string
	scheme   string
	resolver srvResolver
}

// Endpoints resolves the SRV record and returns the URLs of all targets, sorted and without duplicates. Priorities and
// weights are ignored, as every instance needs to be unsealed.
func (e *srvEndpoints) Endpoints(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, srvLookupTimeout)
	defer cancel()

	_, records, err := e.resolver.LookupSRV(ctx, "", "", e.record)
	if err != nil {
		return nil, fmt.Errorf("could not look up SRV record %q: %w", e.record, err)
	}

	var endpoints []string
	for _, record := range records {
		target := strings.TrimSuffix(record.Target, ".")
		// "." as target means the service is explicitly not available, see RFC 2782
		if target == "" {
			continue
		}
		endpoints = append(endpoints, fmt.Sprintf("%s://%s", e.scheme, net.JoinHostPort(target, strconv.Itoa(int(record.Port)))))
	}

	if len(endpoints) == 0 {
		return nil, fmt.Errorf("SRV record %q has no targets", e.record)
	}

	slices.Sort(endpoints)
	return slices.Compact(endpoints), nil
}
