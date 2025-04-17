package rfc2136

import (
	"encoding/base64"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"github.com/miekg/dns"
)

const zone = "example.com."

var echString = "AEj+DQBEAQAgACAdd+scUi0IYFsXnUIU7ko2Nd9+F8M26pAGZVpz/KrWPgAEAAEAAWQVZWNoLXNpdGVzLmV4YW1wbGUubmV0AAA="
var echBytes, _ = base64.StdEncoding.DecodeString(echString)

var testCases = map[dns.RR]libdns.Record{
	&dns.TXT{
		Hdr: dns.RR_Header{
			Name:   "txt.example.com.",
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    220,
		},
		Txt: []string{"hello world"},
	}: {
		Type:  "TXT",
		Name:  "txt",
		Value: "\"hello world\"",
		TTL:   220 * time.Second,
	},

	&dns.TXT{
		Hdr: dns.RR_Header{
			Name:   "txt.example.com.",
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    220,
		},
		Txt: []string{"hello", "world"},
	}: {
		Type:  "TXT",
		Name:  "txt",
		Value: "\"hello\" \"world\"",
		TTL:   220 * time.Second,
	},

	&dns.A{
		Hdr: dns.RR_Header{
			Name:   "a.example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.ParseIP("1.2.3.4"),
	}: {
		Type:  "A",
		Name:  "a",
		Value: "1.2.3.4",
		TTL:   300 * time.Second,
	},

	&dns.AAAA{
		Hdr: dns.RR_Header{
			Name:   "aaaa.example.com.",
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    150,
		},
		AAAA: net.ParseIP("1:2:3:4::"),
	}: {
		Type:  "AAAA",
		Name:  "aaaa",
		Value: "1:2:3:4::",
		TTL:   150 * time.Second,
	},

	&dns.RFC3597{
		Hdr: dns.RR_Header{
			Name:   "privateuse.example.com.",
			Rrtype: 65534,
			Class:  dns.ClassINET,
			Ttl:    150,
		},
		Rdata: "0d10480001",
	}: {
		Type:  "TYPE65534",
		Name:  "privateuse",
		Value: `\# 5 0d10480001`,
		TTL:   150 * time.Second,
	},

	&dns.HTTPS{
		SVCB: dns.SVCB{
			Hdr: dns.RR_Header{
				Name:   "https.example.com.",
				Rrtype: dns.TypeHTTPS,
				Class:  dns.ClassINET,
				Ttl:    150,
			},
			Priority: 2,
			Target:   "target.example.com.",
			Value: []dns.SVCBKeyValue{
				&dns.SVCBAlpn{
					Alpn: []string{"h3", "h2"},
				},
				&dns.SVCBIPv4Hint{
					Hint: []net.IP{net.ParseIP("127.0.0.1")},
				},
				&dns.SVCBIPv6Hint{
					Hint: []net.IP{net.ParseIP("::1")},
				},
				&dns.SVCBECHConfig{
					ECH: echBytes,
				},
			},
		},
	}: {
		Type:     "HTTPS",
		Name:     "https",
		TTL:      150 * time.Second,
		Priority: 2,
		Target:   "target.example.com.",
		Value:    fmt.Sprintf(`2 target.example.com. alpn="h3,h2" ipv4hint="127.0.0.1" ipv6hint="::1" ech="%s"`, echString),
	},

	&dns.MX{
		Hdr: dns.RR_Header{
			Name:   "mx.example.com.",
			Rrtype: dns.TypeMX,
			Class:  dns.ClassINET,
			Ttl:    150,
		},
		Preference: 10,
		Mx:         "mail.example.com.",
	}: {
		Type:     "MX",
		Name:     "mx",
		Value:    "10 mail.example.com.",
		TTL:      150 * time.Second,
		Priority: 10,
	},

	&dns.SRV{
		Hdr: dns.RR_Header{
			Name:   "srv.example.com.",
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET,
			Ttl:    150,
		},
		Priority: 10,
		Weight:   20,
		Port:     443,
		Target:   "service.example.com.",
	}: {
		Type:     "SRV",
		Name:     "srv",
		Value:    "10 20 443 service.example.com.",
		TTL:      150 * time.Second,
		Priority: 10,
		Weight:   20,
	},

	// Bare name
	&dns.A{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.ParseIP("127.0.0.1"),
	}: {
		Type:  "A",
		Name:  "",
		Value: "127.0.0.1",
		TTL:   300 * time.Second,
	},
}

func TestRecordFromRR(t *testing.T) {
	for rr, expected := range testCases {
		converted := recordFromRR(rr, zone)
		if expected != converted {
			t.Errorf("converted record does not match expected\nRR: %#v\nExpected: %#v\nGot: %#v",
				rr, expected, converted)
		}
	}
}

func rrEqual(rr1, rr2 dns.RR) bool {
	return dns.IsDuplicate(rr1, rr2) && rr1.Header().Ttl == rr2.Header().Ttl
}

func TestRecordToRR(t *testing.T) {
	for expected, record := range testCases {
		converted, err := recordToRR(record, zone)
		if err != nil {
			t.Errorf("recordToRR %v: %v", record, err)
		}
		if !rrEqual(expected, converted) {
			t.Errorf("converted rr does not match expected\nRecord: %#v\nExpected: %#v\nGot: %#v",
				record, expected, converted)
		}
	}
}
