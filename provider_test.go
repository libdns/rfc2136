package rfc2136_test

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"github.com/libdns/rfc2136"
)

func filterSOA_NS(records []libdns.Record, zone string) []libdns.Record {
	var filtered []libdns.Record
	for _, rec := range records {
		rr := rec.RR()
		if rr.Type == "SOA" {
			continue
		}
		if rr.Type == "NS" && libdns.RelativeName(rr.Name, zone) == "@" {
			continue
		}
		filtered = append(filtered, rec)
	}
	return filtered
}

func clearAllRecords(ctx context.Context, p rfc2136.Provider, zone string) error {
	records, err := p.GetRecords(ctx, zone)
	if err != nil {
		return err
	}
	records = filterSOA_NS(records, zone)
	_, err = p.DeleteRecords(ctx, zone, records)
	return err
}

func initializeProvider() (context.Context, rfc2136.Provider, string, error) {
	ctx := context.Background()

	zone := os.Getenv("RFC2136_ZONE")
	if zone == "" {
		return ctx, rfc2136.Provider{}, "", fmt.Errorf("RFC2136_ZONE is unset")
	} else {

	}

	provider := rfc2136.Provider{
		KeyName: os.Getenv("RFC2136_KEYNAME"),
		KeyAlg:  os.Getenv("RFC2136_KEYALG"),
		Key:     os.Getenv("RFC2136_KEY"),
		Server:  os.Getenv("RFC2136_SERVER"),
	}

	err := clearAllRecords(ctx, provider, zone)
	if err != nil {
		return ctx, provider, zone, err
	}

	return ctx, provider, zone, nil
}

func compareSVCB(t *testing.T, targetRecord, foundRecord libdns.ServiceBinding) bool {
	if targetRecord.Name != foundRecord.Name {
		return false
	}
	if targetRecord.TTL != foundRecord.TTL {
		return false
	}
	if targetRecord.Priority != foundRecord.Priority {
		return false
	}
	if targetRecord.Target != foundRecord.Target {
		return false
	}
	if !reflect.DeepEqual(targetRecord.Params, foundRecord.Params) {
		return false
	}
	return true
}

func compareRecords(t *testing.T, expectedRecords, actualRecords []libdns.Record, zone string) {
	expectedRecords = filterSOA_NS(expectedRecords, zone)
	actualRecords = filterSOA_NS(actualRecords, zone)

	for _, expectedRecord := range expectedRecords {
		found := false

		for j, actualRecord := range actualRecords {
			expectHttps, expectOk := expectedRecord.(libdns.ServiceBinding)
			actualHttps, actualOk := actualRecord.(libdns.ServiceBinding)
			if expectOk || actualOk {
				if expectOk && actualOk {
					if compareSVCB(t, expectHttps, actualHttps) {
						found = true
						actualRecords = append(actualRecords[:j], actualRecords[j+1:]...)
						break
					}
					continue
				} else {
					continue
				}
			}
			if expectedRecord == actualRecord {
				found = true
				actualRecords = append(actualRecords[:j], actualRecords[j+1:]...)
				break
			}
		}
		if !found {
			t.Errorf("record not found: %#v", expectedRecord)
		}
	}
	if len(actualRecords) > 0 {
		t.Errorf("unexpected records found: %#v", actualRecords)
	}
}

func TestAllTypes(t *testing.T) {
	ctx, provider, zone, err := initializeProvider()
	if err != nil {
		t.Fatal(err)
	}

	// Add one record of every type to make sure they all work
	targetRecords := []libdns.Record{
		libdns.Address{
			Name: "append-address",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("192.0.2.1"),
		},
		libdns.Address{
			Name: "append-address",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("192.0.2.2"),
		},
		libdns.Address{
			Name: "append-address",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("2001:db8::1"),
		},
		libdns.CAA{
			Name:  "append-caa",
			TTL:   300 * time.Second,
			Flags: 128,
			Tag:   "issue",
			Value: "letsencrypt.org",
		},
		libdns.CNAME{
			Name:   "append-cname",
			TTL:    300 * time.Second,
			Target: "example.com.",
		},
		libdns.ServiceBinding{
			Name:     "append-https",
			TTL:      300 * time.Second,
			Scheme:   "https",
			Priority: 1,
			Target:   "append-address." + zone,
			Params: libdns.SvcParams{
				"alpn":     {"h2", "h3"},
				"ipv4hint": {"192.0.2.1", "192.0.2.2"},
				"ipv6hint": {"2001:db8::1"},
				"port":     {"443"},
			},
		},
		libdns.MX{
			Name:       "append-mx",
			TTL:        300 * time.Second,
			Preference: 10,
			Target:     "mx.example.com.",
		},
		libdns.NS{
			Name:   "append-ns",
			TTL:    300 * time.Second,
			Target: "ns1.example.com.",
		},
		libdns.SRV{
			Name:      "append-srv",
			Service:   "exampleservice",
			Transport: "tcp",
			TTL:       300 * time.Second,
			Priority:  10,
			Weight:    20,
			Port:      443,
			Target:    "service.example.com.",
		},
		libdns.ServiceBinding{
			Name:     "append-svcb",
			TTL:      300 * time.Second,
			Scheme:   "dns",
			Priority: 1,
			Target:   ".",
			Params: libdns.SvcParams{
				"alpn": {"dot"},
			},
		},
		libdns.TXT{
			Name: "append-txt",
			TTL:  300 * time.Second,
			Text: "Hello, world!",
		},
	}

	_, err = provider.AppendRecords(ctx, zone, targetRecords)
	if err != nil {
		t.Fatal(err)
	}

	foundRecords, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatal(err)
	}

	compareRecords(t, targetRecords, foundRecords, zone)

	err = clearAllRecords(ctx, provider, zone)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSetRecords(t *testing.T) {
	ctx, provider, zone, err := initializeProvider()
	if err != nil {
		t.Fatal(err)
	}

	// Initialize the zone with an A and an AAAA record
	targetRecords := []libdns.Record{
		libdns.Address{
			Name: "set-address",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("192.0.2.1"),
		},
		libdns.Address{
			Name: "set-address",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("2001:db8::1"),
		},
	}

	_, err = provider.SetRecords(ctx, zone, targetRecords)
	if err != nil {
		t.Fatal(err)
	}

	// Now, we overwrite the A records, add a TXT record to the same name, and
	// add a AAAA record to a different name.
	targetRecords = []libdns.Record{
		libdns.Address{
			Name: "set-address",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("192.0.2.2"),
		},
		libdns.TXT{
			Name: "set-address",
			TTL:  300 * time.Second,
			Text: "Hello, world!",
		},
		libdns.Address{
			Name: "set-address-aaaa",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("2001:db8::2"),
		},
	}

	_, err = provider.SetRecords(ctx, zone, targetRecords)
	if err != nil {
		t.Fatal(err)
	}

	// Now we check that the records were set correctly
	expectedRecords := []libdns.Record{
		libdns.Address{
			Name: "set-address",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("192.0.2.2"),
		},
		libdns.Address{
			Name: "set-address",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("2001:db8::1"),
		},
		libdns.TXT{
			Name: "set-address",
			TTL:  300 * time.Second,
			Text: "Hello, world!",
		},
		libdns.Address{
			Name: "set-address-aaaa",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("2001:db8::2"),
		},
	}

	foundRecords, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatal(err)
	}

	compareRecords(t, expectedRecords, foundRecords, zone)

	err = clearAllRecords(ctx, provider, zone)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAppendRecords(t *testing.T) {
	ctx, provider, zone, err := initializeProvider()
	if err != nil {
		t.Fatal(err)
	}
	expectedRecords := []libdns.Record{}

	// Initialize the zone with an A and an AAAA record
	targetRecords := []libdns.Record{
		libdns.Address{
			Name: "append-address",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("192.0.2.1"),
		},
		libdns.Address{
			Name: "append-address",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("2001:db8::1"),
		},
	}
	expectedRecords = append(expectedRecords, targetRecords...)

	_, err = provider.AppendRecords(ctx, zone, targetRecords)
	if err != nil {
		t.Fatal(err)
	}

	// Now, we add another A record, add a TXT record to the same name, and
	// add a AAAA record to a different name.
	targetRecords = []libdns.Record{
		libdns.Address{
			Name: "append-address",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("192.0.2.2"),
		},
		libdns.TXT{
			Name: "append-address",
			TTL:  300 * time.Second,
			Text: "Hello, world!",
		},
		libdns.Address{
			Name: "append-address-aaaa",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("2001:db8::2"),
		},
	}
	expectedRecords = append(expectedRecords, targetRecords...)

	_, err = provider.AppendRecords(ctx, zone, targetRecords)
	if err != nil {
		t.Fatal(err)
	}

	// Now we check that the records were set correctly
	foundRecords, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatal(err)
	}

	compareRecords(t, expectedRecords, foundRecords, zone)

	err = clearAllRecords(ctx, provider, zone)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDeleteRecords(t *testing.T) {
	ctx, provider, zone, err := initializeProvider()
	if err != nil {
		t.Fatal(err)
	}

	// Initialize the zone with A, AAAA, and TXT records
	targetRecords := []libdns.Record{
		libdns.Address{
			Name: "delete-address",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("192.0.2.1"),
		},
		libdns.Address{
			Name: "delete-address",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("192.0.2.2"),
		},
		libdns.Address{
			Name: "delete-address",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("2001:db8::1"),
		},
		libdns.Address{
			Name: "delete-address",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("2001:db8::2"),
		},
		libdns.Address{
			Name: "delete-address-2",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("192.0.2.1"),
		},
		libdns.Address{
			Name: "delete-address-3",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("192.0.2.1"),
		},
		libdns.Address{
			Name: "delete-address-3",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("192.0.2.2"),
		},
		libdns.Address{
			Name: "delete-everything",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("192.0.2.1"),
		},
		libdns.MX{
			Name:       "delete-everything",
			TTL:        300 * time.Second,
			Preference: 10,
			Target:     "mail.example.com.",
		},
		libdns.TXT{
			Name: "delete-everything",
			TTL:  300 * time.Second,
			Text: "Hello, world!",
		},
	}

	_, err = provider.AppendRecords(ctx, zone, targetRecords)
	if err != nil {
		t.Fatal(err)
	}

	// Now, we delete both A records, the first AAAA record, and everything
	// under "delete-everything".
	targetRecords = []libdns.Record{
		libdns.Address{
			Name: "delete-address",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("192.0.2.1"),
		},
		libdns.Address{
			Name: "delete-address",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("192.0.2.2"),
		},
		libdns.Address{
			Name: "delete-address",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("2001:db8::1"),
		},
		libdns.Address{
			Name: "delete-address-3",
			TTL:  300 * time.Second,
		},
		libdns.RR{
			Name: "delete-everything",
		},
	}

	_, err = provider.DeleteRecords(ctx, zone, targetRecords)
	if err != nil {
		t.Fatal(err)
	}

	// Now we check that the records were deleted correctly
	expectedRecords := []libdns.Record{
		libdns.Address{
			Name: "delete-address",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("2001:db8::2"),
		},
		libdns.Address{
			Name: "delete-address-2",
			TTL:  300 * time.Second,
			IP:   netip.MustParseAddr("192.0.2.1"),
		},
	}

	foundRecords, err := provider.GetRecords(ctx, zone)
	if err != nil {
		t.Fatal(err)
	}

	compareRecords(t, expectedRecords, foundRecords, zone)

	err = clearAllRecords(ctx, provider, zone)
	if err != nil {
		t.Fatal(err)
	}
}
