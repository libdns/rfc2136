RFC2136 provider for [`libdns`](https://github.com/libdns/libdns)
=======================

[![Go Reference](https://pkg.go.dev/badge/test.svg)](https://pkg.go.dev/github.com/libdns/rfc2136)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) using RFC2136 Dynamic Updates, allowing you to manage DNS records.

Example configuration
-----
	p := rfc2136.Provider{
		KeyName: "test",
		Key:     "cWnu6Ju9zOki4f7Q+da2KKGo0KOXbCf6Pej6hW3geC4=",
		KeyAlg:  "hmac-sha256",
		Server:  "1.2.3.4:53",
	}

The optional `Net` field selects the transport protocol for dynamic updates:
`"tcp"` (default) or `"udp"`. Zone transfers (`GetRecords`) always use TCP,
as required by [RFC 5936](https://datatracker.ietf.org/doc/html/rfc5936).
