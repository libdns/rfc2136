module github.com/libdns/rfc2136

go 1.22.0

require (
	github.com/libdns/libdns v1.0.0-beta.1
	github.com/miekg/dns v1.1.64
)

require (
	golang.org/x/mod v0.23.0 // indirect
	golang.org/x/net v0.35.0 // indirect
	golang.org/x/sync v0.11.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/tools v0.30.0 // indirect
)

replace github.com/libdns/libdns v1.0.0-beta.1 => github.com/gucci-on-fleek/libdns v0.0.0-20250419072925-d1ecf5c8f81c // TODO: Remove when libdns/libdns#166 is merged
