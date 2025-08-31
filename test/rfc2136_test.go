package main

import (
	"os"
	"testing"

	"github.com/libdns/libdns/libdnstest"
	"github.com/libdns/rfc2136"
)

func TestRfc2136Provider(t *testing.T) {
	provider := &rfc2136.Provider{
		KeyName: os.Getenv("RFC2136_KEYNAME"),
		KeyAlg:  os.Getenv("RFC2136_KEYALG"),
		Key:     os.Getenv("RFC2136_KEY"),
		Server:  os.Getenv("RFC2136_SERVER"),
	}
	testZone := os.Getenv("RFC2136_ZONE")

	wrappedProvider := libdnstest.WrapNoZoneLister(provider)
	suite := libdnstest.NewTestSuite(wrappedProvider, testZone)
	suite.RunTests(t)
}
