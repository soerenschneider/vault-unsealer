package config

import (
	"testing"
	"time"
)

func validCluster() ClusterConfig {
	return ClusterConfig{
		Endpoints:            []string{"https://vault:8200"},
		CheckIntervalSeconds: 60,
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		conf    UnsealConfig
		wantErr bool
	}{
		{
			name: "valid",
			conf: UnsealConfig{Clusters: []ClusterConfig{validCluster()}},
		},
		{
			name:    "no clusters",
			conf:    UnsealConfig{},
			wantErr: true,
		},
		{
			name:    "empty clusters",
			conf:    UnsealConfig{Clusters: []ClusterConfig{}},
			wantErr: true,
		},
		{
			name: "missing check interval",
			conf: UnsealConfig{Clusters: []ClusterConfig{func() ClusterConfig {
				c := validCluster()
				c.CheckIntervalSeconds = 0
				return c
			}()}},
			wantErr: true,
		},
		{
			name: "check interval too large",
			conf: UnsealConfig{Clusters: []ClusterConfig{func() ClusterConfig {
				c := validCluster()
				c.CheckIntervalSeconds = 3601
				return c
			}()}},
			wantErr: true,
		},
		{
			name: "unique names",
			conf: UnsealConfig{Clusters: []ClusterConfig{
				func() ClusterConfig { c := validCluster(); c.Name = "a"; return c }(),
				validCluster(),
				validCluster(),
			}},
		},
		{
			name: "duplicate names",
			conf: UnsealConfig{Clusters: []ClusterConfig{
				func() ClusterConfig { c := validCluster(); c.Name = "a"; return c }(),
				func() ClusterConfig { c := validCluster(); c.Name = "a"; return c }(),
			}},
			wantErr: true,
		},
		{
			name: "explicit name clashes with default name",
			conf: UnsealConfig{Clusters: []ClusterConfig{
				validCluster(),
				func() ClusterConfig { c := validCluster(); c.Name = "0"; return c }(),
			}},
			wantErr: true,
		},
		{
			name: "key check interval too small",
			conf: UnsealConfig{Clusters: []ClusterConfig{
				func() ClusterConfig { c := validCluster(); c.KeyCheckIntervalSeconds = 10; return c }(),
			}},
			wantErr: true,
		},
		{
			name: "no endpoints",
			conf: UnsealConfig{Clusters: []ClusterConfig{func() ClusterConfig {
				c := validCluster()
				c.Endpoints = []string{}
				return c
			}()}},
			wantErr: true,
		},
		{
			name: "srv instead of endpoints",
			conf: UnsealConfig{Clusters: []ClusterConfig{func() ClusterConfig {
				c := validCluster()
				c.Endpoints = nil
				c.EndpointsSrv = &SrvConfig{Record: "_vault._tcp.example.com", Scheme: "http"}
				return c
			}()}},
		},
		{
			name: "neither endpoints nor srv",
			conf: UnsealConfig{Clusters: []ClusterConfig{func() ClusterConfig {
				c := validCluster()
				c.Endpoints = nil
				return c
			}()}},
			wantErr: true,
		},
		{
			name: "endpoints and srv",
			conf: UnsealConfig{Clusters: []ClusterConfig{func() ClusterConfig {
				c := validCluster()
				c.EndpointsSrv = &SrvConfig{Record: "_vault._tcp.example.com"}
				return c
			}()}},
			wantErr: true,
		},
		{
			name: "srv without record",
			conf: UnsealConfig{Clusters: []ClusterConfig{func() ClusterConfig {
				c := validCluster()
				c.Endpoints = nil
				c.EndpointsSrv = &SrvConfig{}
				return c
			}()}},
			wantErr: true,
		},
		{
			name: "srv with invalid scheme",
			conf: UnsealConfig{Clusters: []ClusterConfig{func() ClusterConfig {
				c := validCluster()
				c.Endpoints = nil
				c.EndpointsSrv = &SrvConfig{Record: "_vault._tcp.example.com", Scheme: "ftp"}
				return c
			}()}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Validate(&tt.conf); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExampleConfigsAreValid(t *testing.T) {
	for _, file := range []string{
		"../../contrib/example-config.json",
		"../../contrib/example-config-static.json",
		"../../contrib/example-config-srv.json",
	} {
		t.Run(file, func(t *testing.T) {
			conf, err := ReadConfig(file)
			if err != nil {
				t.Fatalf("ReadConfig() error = %v", err)
			}
			if err := Validate(conf); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			for _, cluster := range conf.Clusters {
				if _, err := GetRetrieveConfig(cluster); err != nil {
					t.Fatalf("GetRetrieveConfig() error = %v", err)
				}
			}
		})
	}
}

func TestKeyCheckIntervalOrDefault(t *testing.T) {
	if got := (ClusterConfig{}).KeyCheckIntervalOrDefault(); got != 24*time.Hour {
		t.Fatalf("expected default of 24h, got %s", got)
	}
	if got := (ClusterConfig{KeyCheckIntervalSeconds: 300}).KeyCheckIntervalOrDefault(); got != 5*time.Minute {
		t.Fatalf("expected 5m, got %s", got)
	}
}
