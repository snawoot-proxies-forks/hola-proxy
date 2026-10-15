package main

import (
	"testing"
)

func testTunnels() *ZGetTunnelsResponse {
	return &ZGetTunnelsResponse{
		AgentKey: "key",
		IPList: map[string]string{
			"zagent1.hola.org": "1.1.1.1",
			"zagent2.hola.org": "2.2.2.2",
			"zagent3.hola.org": "3.3.3.3",
		},
		Port: PortMap{
			Direct:    22222,
			Peer:      22223,
			Hola:      22224,
			Trial:     22225,
			TrialPeer: 22226,
		},
		Protocol: map[string]string{
			"zagent1.hola.org": "HTTP",
			"zagent2.hola.org": "HTTP",
			"zagent3.hola.org": "SOCKS5",
		},
		Ztun: map[string][]string{
			"de": {"zagent2.hola.org:22222", "zagent1.hola.org:22222"},
		},
	}
}

func TestGetEndpointsDeterministicOrder(t *testing.T) {
	eps, err := get_endpoints(testTunnels(), "direct", true, "")
	if err != nil {
		t.Fatalf("get_endpoints failed: %v", err)
	}
	if len(eps) != 2 {
		t.Fatalf("expected 2 endpoints (SOCKS5 filtered), got %d", len(eps))
	}
	if eps[0].Host != "2.2.2.2" || eps[1].Host != "1.1.1.1" {
		t.Fatalf("expected ztun order preserved (zagent2, zagent1), got %s then %s",
			eps[0].Host, eps[1].Host)
	}
	if eps[0].Port != 22222 || eps[0].TLSName != "zagent2.hola.org" {
		t.Fatalf("unexpected endpoint: %+v", eps[0])
	}
	if eps[0].ExpectIP != "2.2.2.2" {
		t.Fatalf("expected ExpectIP to be set, got %+v", eps[0])
	}
}

func TestGetEndpointsSchemePrefix(t *testing.T) {
	tuns := testTunnels()
	tuns.Ztun["de"] = []string{"HTTP zagent1.hola.org:443", "SOCKS5 zagent3.hola.org:1080"}
	eps, err := get_endpoints(tuns, "direct", true, "")
	if err != nil {
		t.Fatalf("get_endpoints failed: %v", err)
	}
	if len(eps) != 1 || eps[0].Host != "1.1.1.1" {
		t.Fatalf("expected only HTTP-capable zagent1, got %+v", eps)
	}
}

func TestGetEndpointsPortMapping(t *testing.T) {
	tuns := testTunnels()
	cases := []struct {
		typ   string
		trial bool
		want  uint16
	}{
		{"direct", true, 22222},
		{"direct", false, 22225},
		{"peer", true, 22223},
		{"peer", false, 22226},
	}
	for _, c := range cases {
		eps, err := get_endpoints(tuns, c.typ, c.trial, "")
		if err != nil {
			t.Fatalf("get_endpoints(%s, trial=%v) failed: %v", c.typ, c.trial, err)
		}
		if len(eps) == 0 || eps[0].Port != c.want {
			t.Fatalf("type=%s trial=%v: expected port %d, got %+v", c.typ, c.trial, c.want, eps)
		}
	}
}

func TestGetEndpointsForcePortField(t *testing.T) {
	eps, err := get_endpoints(testTunnels(), "direct", true, "24232")
	if err != nil {
		t.Fatalf("get_endpoints failed: %v", err)
	}
	if len(eps) == 0 || eps[0].Port != 24232 {
		t.Fatalf("expected forced port 24232, got %+v", eps)
	}
	// Named port field override.
	eps, err = get_endpoints(testTunnels(), "direct", true, "peer")
	if err != nil {
		t.Fatalf("get_endpoints failed: %v", err)
	}
	if len(eps) == 0 || eps[0].Port != 22223 {
		t.Fatalf("expected peer port 22223, got %+v", eps)
	}
}

func TestGetEndpointsFallbackIPList(t *testing.T) {
	tuns := testTunnels()
	tuns.Ztun = nil
	eps, err := get_endpoints(tuns, "direct", true, "")
	if err != nil {
		t.Fatalf("get_endpoints failed: %v", err)
	}
	if len(eps) != 2 {
		t.Fatalf("expected 2 endpoints from ip_list fallback, got %d", len(eps))
	}
	// Sorted by hostname: zagent1, zagent2.
	if eps[0].Host != "1.1.1.1" || eps[1].Host != "2.2.2.2" {
		t.Fatalf("expected sorted ip_list order, got %+v", eps)
	}
}

func TestMergeCountries(t *testing.T) {
	merged := mergeCountries(CountryList{"de", "us", "ge"})
	if len(merged) == 0 {
		t.Fatal("empty merged list")
	}
	for i := 1; i < len(merged); i++ {
		if merged[i] <= merged[i-1] {
			t.Fatalf("merged list not sorted/deduped: %v", merged)
		}
	}
	for _, extra := range EXTRA_COUNTRIES {
		found := false
		for _, c := range merged {
			if c == extra {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("extra country %s missing from merged list", extra)
		}
	}
}
