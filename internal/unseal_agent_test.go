package internal

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/soerenschneider/vault-unsealer/v2/internal/config"
	"github.com/soerenschneider/vault-unsealer/v2/internal/unsealing"
	"github.com/soerenschneider/vault-unsealer/v2/internal/vault"
)

func metricValue(t *testing.T, metric prometheus.Metric) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := metric.Write(m); err != nil {
		t.Fatal(err)
	}
	if m.Counter != nil {
		return m.Counter.GetValue()
	}
	return m.Gauge.GetValue()
}

// fakeVaultClient mimics Vault's shamir unsealing: duplicate key shares are ignored, the instance is unsealed once the
// threshold of distinct shares is reached, and shares sent to an unsealed instance are accepted but ignored.
type fakeVaultClient struct {
	mutex      sync.Mutex
	sealed     bool
	unsealKeys []string
	// threshold of key shares, defaults to 1
	threshold int
	// validKeys are the only accepted keys, if set
	validKeys []string
	parts     map[string]bool
	resets    int
}

func (c *fakeVaultClient) status() *vault.SealedStatus {
	threshold := max(c.threshold, 1)
	return &vault.SealedStatus{Sealed: c.sealed, Threshold: threshold, Progress: len(c.parts)}
}

func (c *fakeVaultClient) GetSealedStatus(_ context.Context, _ string) (*vault.SealedStatus, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.status(), nil
}

func (c *fakeVaultClient) Unseal(_ context.Context, _ string, unsealKey string) (*vault.SealedStatus, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.unsealKeys = append(c.unsealKeys, unsealKey)
	if !c.sealed {
		return c.status(), nil
	}
	if len(c.validKeys) > 0 && !slices.Contains(c.validKeys, unsealKey) {
		c.parts = nil
		return nil, vault.ErrUnsealKeyRejected
	}
	if c.parts == nil {
		c.parts = map[string]bool{}
	}
	c.parts[unsealKey] = true
	if len(c.parts) >= max(c.threshold, 1) {
		c.sealed = false
		c.parts = nil
	}
	return c.status(), nil
}

func (c *fakeVaultClient) seal() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.sealed = true
}

func (c *fakeVaultClient) ResetUnseal(_ context.Context, _ string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.resets++
	c.parts = nil
	return nil
}

// flakyRetriever fails the first n calls.
type flakyRetriever struct {
	failures int
	calls    int
}

func (r *flakyRetriever) RetrieveUnsealKey(_ context.Context) (string, error) {
	r.calls++
	if r.calls <= r.failures {
		return "", errors.New("key source unavailable")
	}
	return "key", nil
}

func (r *flakyRetriever) Name() string {
	return "flaky"
}

func TestUnsealAgent_SurvivesFailedStartupCheck(t *testing.T) {
	client := &fakeVaultClient{sealed: true}
	// fails the startup check and the first unseal attempt, succeeds afterwards
	retriever := &flakyRetriever{failures: 2}
	conf := config.ClusterConfig{Endpoints: []string{"http://startup-check"}}

	agent, err := NewUnsealAgent("startup-check", conf, client, []unsealing.UnsealKeyRetriever{retriever})
	if err != nil {
		t.Fatal(err)
	}

	retrievalErrorsBefore := metricValue(t, UnsealKeyRetrievalErrors.WithLabelValues("startup-check", "flaky"))
	ctx := context.Background()
	agent.checkKeyRetrievers(ctx)
	agent.conditionallyUnsealInstances(ctx)
	if !client.sealed {
		t.Fatal("expected instance to still be sealed while key retrieval fails")
	}

	agent.conditionallyUnsealInstances(ctx)
	if client.sealed || len(client.unsealKeys) != 1 {
		t.Fatalf("expected instance to be unsealed once key retrieval works, got sealed=%t keys=%v", client.sealed, client.unsealKeys)
	}

	if got := metricValue(t, UnsealKeyRetrievalErrors.WithLabelValues("startup-check", "flaky")) - retrievalErrorsBefore; got != 2 {
		t.Fatalf("expected 2 retrieval errors for cluster, got %f", got)
	}
	if got := metricValue(t, UnsealedStatus.WithLabelValues("http://startup-check")); got != 1 {
		t.Fatalf("expected status to be updated to unsealed (1) right after unsealing, got %f", got)
	}
}

func TestUnsealAgent_RunStopsOnCancel(t *testing.T) {
	client := &fakeVaultClient{sealed: false}
	conf := config.ClusterConfig{Endpoints: []string{"http://run"}, CheckIntervalSeconds: 60}
	agent, err := NewUnsealAgent("run", conf, client, []unsealing.UnsealKeyRetriever{&flakyRetriever{failures: 100}})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		agent.Run(ctx)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not stop after context was cancelled")
	}

	if got := metricValue(t, UnsealedStatus.WithLabelValues("http://run")); got != 1 {
		t.Fatalf("expected instance to be reported as unsealed (1), got %f", got)
	}
}

// sourceRetriever returns whatever key is currently stored in the source.
type sourceRetriever struct {
	key   string
	calls int
}

func (r *sourceRetriever) RetrieveUnsealKey(_ context.Context) (string, error) {
	r.calls++
	return r.key, nil
}

func (r *sourceRetriever) Name() string {
	return "source"
}

func TestUnsealAgent_RefreshesCachedKeyWhenRejected(t *testing.T) {
	instance := "http://rekeyed"
	source := &sourceRetriever{key: "old-key"}
	cached, err := unsealing.NewCachedUnsealKeyRetriever(source)
	if err != nil {
		t.Fatal(err)
	}

	client := &fakeVaultClient{sealed: true, validKeys: []string{"old-key"}}
	agent, err := NewUnsealAgent("rekeyed", config.ClusterConfig{Endpoints: []string{instance}}, client, []unsealing.UnsealKeyRetriever{cached})
	if err != nil {
		t.Fatal(err)
	}

	// key gets cached
	if err := agent.conditionalUnsealInstance(context.Background(), instance); err != nil {
		t.Fatal(err)
	}

	// Vault is rekeyed and the new key is stored in the source, the cache still holds the old key
	client.seal()
	client.validKeys = []string{"new-key"}
	source.key = "new-key"

	// the rejection of the outdated key is only logged as warning, as unsealing succeeds with the refreshed key
	if err := agent.conditionalUnsealInstance(context.Background(), instance); err != nil {
		t.Fatal(err)
	}
	if client.sealed {
		t.Fatalf("expected instance to be unsealed with the refreshed key, submitted keys: %v", client.unsealKeys)
	}
	if client.resets != 1 || source.calls != 2 {
		t.Fatalf("expected one reset and the key to be fetched again, got resets=%d calls=%d", client.resets, source.calls)
	}
	want := []string{"old-key", "old-key", "new-key"}
	if fmt.Sprint(client.unsealKeys) != fmt.Sprint(want) {
		t.Fatalf("expected submitted keys %v, got %v", want, client.unsealKeys)
	}
}

func TestUnsealAgent_NoRetryWithoutCache(t *testing.T) {
	instance := "http://wrong-key"
	source := &sourceRetriever{key: "wrong-key"}
	client := &fakeVaultClient{sealed: true, validKeys: []string{"right-key"}}
	agent, err := NewUnsealAgent("wrong-key", config.ClusterConfig{Endpoints: []string{instance}}, client, []unsealing.UnsealKeyRetriever{source})
	if err != nil {
		t.Fatal(err)
	}

	if err := agent.conditionalUnsealInstance(context.Background(), instance); err == nil {
		t.Fatal("expected error")
	}
	if client.resets != 0 || source.calls != 1 {
		t.Fatalf("expected no retry without cache, got resets=%d calls=%d", client.resets, source.calls)
	}
}

func TestUnsealAgent_RetriesOnlyOnce(t *testing.T) {
	instance := "http://always-wrong"
	source := &sourceRetriever{key: "wrong-key"}
	cached, _ := unsealing.NewCachedUnsealKeyRetriever(source)
	client := &fakeVaultClient{sealed: true, validKeys: []string{"right-key"}}
	agent, err := NewUnsealAgent("always-wrong", config.ClusterConfig{Endpoints: []string{instance}}, client, []unsealing.UnsealKeyRetriever{cached})
	if err != nil {
		t.Fatal(err)
	}

	if err := agent.conditionalUnsealInstance(context.Background(), instance); err == nil {
		t.Fatal("expected error")
	}
	if client.resets != 1 || source.calls != 2 || len(client.unsealKeys) != 2 {
		t.Fatalf("expected exactly one retry, got resets=%d calls=%d keys=%v", client.resets, source.calls, client.unsealKeys)
	}
}

func TestStartMetricsServer_Shutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- StartMetricsServer(ctx, "127.0.0.1:0")
	}()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("metrics server did not shut down")
	}
}

// staticRetriever returns a fixed key or error.
type staticRetriever struct {
	name  string
	key   string
	err   error
	mutex sync.Mutex
	calls int
}

func (r *staticRetriever) RetrieveUnsealKey(_ context.Context) (string, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.calls++
	if r.err != nil {
		return "", r.err
	}
	return r.key, nil
}

func (r *staticRetriever) Name() string {
	return r.name
}

func (r *staticRetriever) setErr(err error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.err = err
}

func newTestAgent(t *testing.T, name string, client *fakeVaultClient, retrievers ...unsealing.UnsealKeyRetriever) *UnsealAgent {
	t.Helper()
	agent, err := NewUnsealAgent(name, config.ClusterConfig{Endpoints: []string{"http://" + name}}, client, retrievers)
	if err != nil {
		t.Fatal(err)
	}
	return agent
}

func TestUnsealAgent_FetchesAllKeysButStopsSubmittingOnceUnsealed(t *testing.T) {
	client := &fakeVaultClient{sealed: true, threshold: 2}
	retrievers := []*staticRetriever{{name: "a", key: "key-a"}, {name: "b", key: "key-b"}, {name: "spare", key: "key-c"}}
	agent := newTestAgent(t, "early-stop", client, retrievers[0], retrievers[1], retrievers[2])

	if err := agent.conditionalUnsealInstance(context.Background(), "http://early-stop"); err != nil {
		t.Fatal(err)
	}
	if client.sealed {
		t.Fatal("expected instance to be unsealed")
	}
	if fmt.Sprint(client.unsealKeys) != fmt.Sprint([]string{"key-a", "key-b"}) {
		t.Fatalf("expected only the keys needed for the threshold to be submitted, got %v", client.unsealKeys)
	}
	for _, r := range retrievers {
		if r.calls != 1 {
			t.Fatalf("expected all retrievers to be queried once, retriever %s was queried %d times", r.name, r.calls)
		}
	}
}

func TestUnsealAgent_SpareKeyCompensatesForFailingSource(t *testing.T) {
	client := &fakeVaultClient{sealed: true, threshold: 2}
	down := &staticRetriever{name: "down", err: errors.New("unavailable")}
	agent := newTestAgent(t, "spare", client, down, &staticRetriever{name: "b", key: "key-b"}, &staticRetriever{name: "spare", key: "key-c"})
	retrievalErrorsBefore := metricValue(t, UnsealKeyRetrievalErrors.WithLabelValues("spare", "down"))

	if err := agent.conditionalUnsealInstance(context.Background(), "http://spare"); err != nil {
		t.Fatal(err)
	}
	if client.sealed {
		t.Fatal("expected instance to be unsealed using the spare key")
	}
	if got := metricValue(t, UnsealKeyRetrievalErrors.WithLabelValues("spare", "down")) - retrievalErrorsBefore; got != 1 {
		t.Fatalf("expected failing source to be counted, got %f", got)
	}
}

func TestUnsealAgent_CachedSpareKeySurvivesSourceOutage(t *testing.T) {
	client := &fakeVaultClient{sealed: true, threshold: 2}
	a := &staticRetriever{name: "a", key: "key-a"}
	b := &staticRetriever{name: "b", key: "key-b"}
	spareSource := &staticRetriever{name: "spare", key: "key-c"}
	spare, _ := unsealing.NewCachedUnsealKeyRetriever(spareSource)
	agent := newTestAgent(t, "cached-spare", client, a, b, spare)

	// first unseal only needs a and b, but the spare key is fetched and cached anyway
	if err := agent.conditionalUnsealInstance(context.Background(), "http://cached-spare"); err != nil {
		t.Fatal(err)
	}

	// later, the spare's source and one of the other sources are down
	client.seal()
	spareSource.setErr(errors.New("unavailable"))
	b.setErr(errors.New("unavailable"))

	_ = agent.conditionalUnsealInstance(context.Background(), "http://cached-spare")
	if client.sealed {
		t.Fatalf("expected instance to be unsealed with the cached spare key, submitted keys: %v", client.unsealKeys)
	}
}

func TestUnsealAgent_DuplicateKeysAreSubmittedOnce(t *testing.T) {
	client := &fakeVaultClient{sealed: true, threshold: 2}
	agent := newTestAgent(t, "duplicates", client, &staticRetriever{name: "a", key: "same"}, &staticRetriever{name: "b", key: "same"})

	if err := agent.conditionalUnsealInstance(context.Background(), "http://duplicates"); err == nil {
		t.Fatal("expected error as threshold can not be reached")
	}
	if fmt.Sprint(client.unsealKeys) != fmt.Sprint([]string{"same"}) {
		t.Fatalf("expected duplicate key to be submitted once, got %v", client.unsealKeys)
	}
}

func TestUnsealAgent_ThresholdNotReachable(t *testing.T) {
	client := &fakeVaultClient{sealed: true, threshold: 3}
	agent := newTestAgent(t, "insufficient", client, &staticRetriever{name: "a", key: "key-a"}, &staticRetriever{name: "b", key: "key-b"})

	if err := agent.conditionalUnsealInstance(context.Background(), "http://insufficient"); err == nil {
		t.Fatal("expected error as threshold can not be reached")
	}
	// partial keys are still submitted, so an operator can provide the missing ones
	if len(client.unsealKeys) != 2 || client.status().Progress != 2 {
		t.Fatalf("expected partial progress 2/3, got keys=%v progress=%d", client.unsealKeys, client.status().Progress)
	}
}

func TestUnsealAgent_KeyCheckBypassesCache(t *testing.T) {
	source := &staticRetriever{name: "cached-source", key: "old-key"}
	cached, _ := unsealing.NewCachedUnsealKeyRetriever(source)
	agent := newTestAgent(t, "key-check", &fakeVaultClient{}, cached)

	agent.checkKeyRetrievers(context.Background())
	if got := metricValue(t, KeyRetrieverHealthy.WithLabelValues("key-check", cached.Name())); got != 1 {
		t.Fatalf("expected key source to be healthy, got %f", got)
	}

	// source changes, e.g. after a rekey: the check fetches the new key although an old one is cached
	source.key = "new-key"
	agent.checkKeyRetrievers(context.Background())
	if key, _ := cached.RetrieveUnsealKey(context.Background()); key != "new-key" {
		t.Fatalf("expected cache to be refreshed by key check, got %q", key)
	}

	// source fails: the check reports it, but the cached key is kept
	source.setErr(errors.New("unavailable"))
	agent.checkKeyRetrievers(context.Background())
	if got := metricValue(t, KeyRetrieverHealthy.WithLabelValues("key-check", cached.Name())); got != 0 {
		t.Fatalf("expected key source to be reported as failing although a key is cached, got %f", got)
	}
	if key, err := cached.RetrieveUnsealKey(context.Background()); err != nil || key != "new-key" {
		t.Fatalf("expected cached key to be kept when the source fails, got %q, %v", key, err)
	}
	if source.calls != 3 {
		t.Fatalf("expected every check to query the source, got %d calls", source.calls)
	}
}

func TestUnsealAgent_RunChecksKeysPeriodically(t *testing.T) {
	source := &staticRetriever{name: "periodic", key: "key"}
	conf := config.ClusterConfig{Endpoints: []string{"http://periodic"}, CheckIntervalSeconds: 60, KeyCheckIntervalSeconds: 1}
	agent, err := NewUnsealAgent("periodic", conf, &fakeVaultClient{}, []unsealing.UnsealKeyRetriever{source})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		agent.Run(ctx)
		close(done)
	}()

	// startup check plus at least one periodic check
	deadline := time.Now().Add(5 * time.Second)
	for {
		source.mutex.Lock()
		calls := source.calls
		source.mutex.Unlock()
		if calls >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected periodic key check, got %d calls", calls)
		}
		time.Sleep(50 * time.Millisecond)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not stop after context was cancelled")
	}
}
