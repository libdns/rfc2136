module github.com/libdns/rfc2136/test

go 1.22.0

toolchain go1.24.8

require (
	github.com/libdns/libdns v1.2.0-alpha.1
	github.com/libdns/rfc2136 v1.0.1
)

require (
	github.com/miekg/dns v1.1.64 // indirect
	golang.org/x/mod v0.23.0 // indirect
	golang.org/x/net v0.35.0 // indirect
	golang.org/x/sync v0.11.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/tools v0.30.0 // indirect
)

replace github.com/libdns/rfc2136 => ../
