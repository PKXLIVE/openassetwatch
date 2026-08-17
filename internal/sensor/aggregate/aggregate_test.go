package aggregate

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openassetwatch/openassetwatch/internal/sensor/contract"
	"github.com/openassetwatch/openassetwatch/internal/sensor/decode"
)

func observation(mac, ip, hostname, protocol, kind, value string, vlan *int, at time.Time) decode.Evidence {
	return decode.Evidence{
		MAC: mac, IP: ip, Hostname: hostname, Protocol: protocol, Kind: kind,
		Value: value, VLANID: vlan, Confidence: 0.8, ObservedAt: at,
	}
}

func TestAggregatorCorrelatesOnlyWithinSiteMACAndVLAN(t *testing.T) {
	base := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	vlan10, vlan20 := 10, 20
	agg, err := New(Config{SiteID: "site-demo", MaxDevices: 4, TTL: time.Minute})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := agg.Add(observation("02:00:5e:10:00:01", "192.0.2.10", "printer", "arp", "reply", "192.0.2.10", &vlan10, base)); err != nil {
		t.Fatal(err)
	}
	if err := agg.Add(observation("02:00:5e:10:00:01", "192.0.2.11", "printer-new", "dhcpv4", "client-hostname", "printer-new", &vlan10, base.Add(time.Second))); err != nil {
		t.Fatal(err)
	}
	if err := agg.Add(observation("02:00:5e:10:00:01", "192.0.2.12", "printer-new", "arp", "reply", "192.0.2.12", &vlan20, base)); err != nil {
		t.Fatal(err)
	}
	if err := agg.Add(observation("02:00:5e:10:00:02", "192.0.2.13", "printer-new", "arp", "reply", "192.0.2.13", &vlan10, base)); err != nil {
		t.Fatal(err)
	}
	assets := agg.Snapshot(base.Add(2*time.Second), 10)
	if len(assets) != 3 {
		t.Fatalf("asset count = %d, want 3", len(assets))
	}
	for _, asset := range assets {
		if asset.VLANID == nil {
			t.Fatalf("asset omitted local VLAN scope: %+v", asset)
		}
		foundVLAN := false
		for _, item := range asset.Evidence {
			foundVLAN = foundVLAN || item.Protocol == "vlan"
		}
		if !foundVLAN {
			t.Fatalf("asset omitted VLAN wire evidence: %+v", asset)
		}
	}
}

func TestAggregatorCapsDevicesIPsEvidenceAndExpiresState(t *testing.T) {
	base := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	agg, err := New(Config{
		SiteID: "site-demo", MaxDevices: 1, MaxIPsPerDevice: 1,
		MaxEvidencePerDevice: 1, TTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	first := observation("02:00:5e:10:00:01", "192.0.2.10", "", "arp", "reply", "192.0.2.10", nil, base)
	if err := agg.Add(first); err != nil {
		t.Fatal(err)
	}
	second := observation(first.MAC, "192.0.2.11", "", "dhcpv4", "requested-ip", "192.0.2.11", nil, base.Add(time.Second))
	if err := agg.Add(second); !errors.Is(err, ErrCapacity) {
		t.Fatalf("second evidence = %v, want capacity error", err)
	}
	other := observation("02:00:5e:10:00:02", "192.0.2.12", "", "arp", "reply", "192.0.2.12", nil, base)
	if err := agg.Add(other); !errors.Is(err, ErrCapacity) {
		t.Fatalf("second device = %v, want capacity error", err)
	}
	assets := agg.Snapshot(base.Add(2*time.Second), contract.MaxAssets)
	if len(assets) != 1 || assets[0].PrimaryIP != "192.0.2.10" || len(assets[0].Evidence) != 1 {
		t.Fatalf("bounded snapshot = %+v", assets)
	}
	if removed := agg.Expire(base.Add(time.Minute + 2*time.Second)); removed != 1 {
		t.Fatalf("Expire() removed %d, want 1", removed)
	}
	if devices, dropped := agg.Counts(); devices != 0 || dropped < 2 {
		t.Fatalf("Counts() = %d, %d", devices, dropped)
	}
}

func TestAggregatorRejectsUnsafeOrUnboundedInputs(t *testing.T) {
	for name, config := range map[string]Config{
		"site":       {SiteID: "bad/site"},
		"devices":    {SiteID: "site", MaxDevices: MaxDevicesAbsolute + 1},
		"ips":        {SiteID: "site", MaxIPsPerDevice: MaxIPsPerDeviceAbsolute + 1},
		"evidence":   {SiteID: "site", MaxEvidencePerDevice: contract.MaxEvidence + 1},
		"expiration": {SiteID: "site", TTL: MaxTTLAbsolute + time.Second},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(config); err == nil {
				t.Fatal("New() unexpectedly accepted unsafe configuration")
			}
		})
	}

	base := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	agg, err := New(Config{SiteID: "site"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []decode.Evidence{
		observation("01:00:5e:00:00:01", "", "", "arp", "reply", "x", nil, base),
		observation("02:00:5e:00:00:01", "", "", "active-scan", "port", "22", nil, base),
		observation("02:00:5e:00:00:01", "", strings.Repeat("h", MaxHostnameLength+1), "arp", "reply", "x", nil, base),
		observation("02:00:5e:00:00:01", "", "", "mdns", "service-name", strings.Repeat("s", MaxServiceNameLength+1), nil, base),
		observation("02:00:5e:00:00:01", "", "", "ssdp", "server", strings.Repeat("s", MaxSSDPMetadataLength+1), nil, base),
	}
	badVLAN := MaxVLANID + 1
	tests = append(tests, observation("02:00:5e:00:00:01", "", "", "arp", "reply", "x", &badVLAN, base))
	for index, item := range tests {
		if err := agg.Add(item); err == nil {
			t.Errorf("unsafe observation %d unexpectedly succeeded", index)
		}
	}
}
