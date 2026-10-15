package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestZGetTunnelsBlocked(t *testing.T) {
	var res ZGetTunnelsResponse
	err := json.Unmarshal([]byte(`{"blocked":true,"permanent":false}`), &res)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if !res.Blocked {
		t.Fatal("expected Blocked to be true")
	}
	if res.Permanent {
		t.Fatal("expected Permanent to be false")
	}
}

func TestZGetTunnelsPermanent(t *testing.T) {
	var res ZGetTunnelsResponse
	err := json.Unmarshal([]byte(`{"blocked":true,"permanent":true}`), &res)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if !res.Blocked || !res.Permanent {
		t.Fatalf("expected blocked+permanent, got %+v", res)
	}
}

func TestZGetTunnelsNormal(t *testing.T) {
	var res ZGetTunnelsResponse
	err := json.Unmarshal([]byte(`{
		"agent_key": "secret",
		"ip_list": {"zagent1.hola.org": "1.2.3.4"},
		"port": {"direct": 22222, "peer": 22223, "hola": 22224, "trial": 22225, "trial_peer": 22226},
		"ztun": {"de": ["zagent1.hola.org:22222"]}
	}`), &res)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if res.Blocked || res.Permanent {
		t.Fatalf("expected no blocked flags, got %+v", res)
	}
	if res.Port.TrialPeer != 22226 {
		t.Fatalf("unexpected trial_peer port: %d", res.Port.TrialPeer)
	}
}

func TestEnsureTransactionPermanentBanAborts(t *testing.T) {
	calls := 0
	err := EnsureTransaction(context.Background(), time.Second, func(ctx context.Context, client *http.Client) error {
		calls++
		return PermanentBanError
	})
	if !errors.Is(err, PermanentBanError) {
		t.Fatalf("expected PermanentBanError, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected abort after first attempt, got %d calls", calls)
	}
}

func TestEnsureTransactionSuccess(t *testing.T) {
	calls := 0
	err := EnsureTransaction(context.Background(), time.Second, func(ctx context.Context, client *http.Client) error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected a single attempt, got %d calls", calls)
	}
}
