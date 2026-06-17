package network

import (
	"testing"
	"time"

	"github.com/openassetwatch/openassetwatch/pkg/models"
)

func TestParseProcARPFiltersUnsafeEntries(t *testing.T) {
	output := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
224.0.0.251      0x1         0x2         01:00:5e:00:00:fb     *        eth0
192.168.1.20     0x1         0x0         00:00:00:00:00:00     *        eth0
`

	entries := parseProcARP(output)
	if len(entries) != 1 {
		t.Fatalf("parseProcARP length = %d, want 1", len(entries))
	}
	if entries[0].IPAddress != "192.168.1.1" || entries[0].MACAddress != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("unexpected proc arp entry: %+v", entries[0])
	}
}

func TestParseArpAWindowsAndDarwinFormats(t *testing.T) {
	output := `Interface: 192.168.1.10 --- 0x6
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
? (192.168.1.2) at 11:22:33:44:55:66 on en0 ifscope [ethernet]
? (192.168.1.3) at (incomplete) on en0 ifscope [ethernet]
`

	entries := parseArpA(output)
	if len(entries) != 2 {
		t.Fatalf("parseArpA length = %d, want 2", len(entries))
	}
	if entries[0].Interface != "" || entries[0].MACAddress != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("unexpected windows arp entry: %+v", entries[0])
	}
	if entries[1].Interface != "en0" || entries[1].MACAddress != "11:22:33:44:55:66" {
		t.Fatalf("unexpected darwin arp entry: %+v", entries[1])
	}
}

func TestParsersHandleMalformedOrMissingOutput(t *testing.T) {
	if entries := parseWindowsGetNetNeighbor("not json"); len(entries) != 0 {
		t.Fatalf("parseWindowsGetNetNeighbor malformed length = %d, want 0", len(entries))
	}
	if gateway := parseDarwinDefaultRoute("interface: en0"); gateway != nil {
		t.Fatalf("parseDarwinDefaultRoute without gateway = %+v, want nil", gateway)
	}
	if entries := parseArpA(""); len(entries) != 0 {
		t.Fatalf("parseArpA empty length = %d, want 0", len(entries))
	}
}

func TestStampNeighborsSetsCollectedAt(t *testing.T) {
	collectedAt := time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)
	entries := stampNeighbors([]models.NetworkNeighbor{{IPAddress: "192.168.1.1", MACAddress: "aa:bb:cc:dd:ee:ff"}}, collectedAt)
	if len(entries) != 1 {
		t.Fatalf("stampNeighbors length = %d, want 1", len(entries))
	}
	if !entries[0].CollectedAt.Equal(collectedAt) {
		t.Fatalf("stampNeighbors CollectedAt = %s, want %s", entries[0].CollectedAt, collectedAt)
	}
}

func TestDefaultGatewayFromProcRoute(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/route"
	content := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	0101A8C0	0003	0	0	100	00000000	0	0	0
wlan0	00000000	FE01A8C0	0003	0	0	50	00000000	0	0	0
`
	if err := writeTestFile(path, content); err != nil {
		t.Fatal(err)
	}

	gateway := defaultGatewayFromProcRoute(path)
	if gateway == nil {
		t.Fatal("defaultGatewayFromProcRoute returned nil")
	}
	if gateway.Address != "192.168.1.254" || gateway.Interface != "wlan0" {
		t.Fatalf("unexpected gateway: %+v", gateway)
	}
}

func TestParseWindowsGetNetNeighborAcceptsSingleObject(t *testing.T) {
	output := `{"IPAddress":"192.168.1.1","LinkLayerAddress":"aa-bb-cc-dd-ee-ff","InterfaceAlias":"Ethernet","State":"Reachable"}`
	entries := parseWindowsGetNetNeighbor(output)
	if len(entries) != 1 {
		t.Fatalf("parseWindowsGetNetNeighbor length = %d, want 1", len(entries))
	}
	if entries[0].Interface != "Ethernet" || entries[0].State != "reachable" {
		t.Fatalf("unexpected windows neighbor entry: %+v", entries[0])
	}
}

func TestParseDarwinDefaultRoute(t *testing.T) {
	output := `   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
`
	gateway := parseDarwinDefaultRoute(output)
	if gateway == nil {
		t.Fatal("parseDarwinDefaultRoute returned nil")
	}
	if gateway.Address != "192.168.1.1" || gateway.Interface != "en0" {
		t.Fatalf("unexpected darwin gateway: %+v", gateway)
	}
}
