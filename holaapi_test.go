package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCommonParams(t *testing.T) {
	params := commonParams("1.2.3")
	for _, k := range []string{"rmt_ver", "ext_ver", "browser", "product", "lccgi"} {
		if params.Get(k) == "" {
			t.Fatalf("commonParams missing %s", k)
		}
	}
	if params.Get("ext_ver") != "1.2.3" || params.Get("rmt_ver") != "1.2.3" {
		t.Fatal("ext_ver/rmt_ver mismatch")
	}
}

func TestEnsureTransactionPermanentBanAborts(t *testing.T) {
	calls := 0
	err := EnsureTransaction(context.Background(), time.Second, "", func(ctx context.Context, purl string) error {
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
	err := EnsureTransaction(context.Background(), time.Second, "", func(ctx context.Context, purl string) error {
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
