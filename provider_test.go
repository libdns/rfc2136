package rfc2136

import "testing"

func TestClientNet(t *testing.T) {
	tests := []struct {
		name    string
		net     string
		wantNet string
		wantErr bool
	}{
		{name: "default is tcp", net: "", wantNet: "tcp"},
		{name: "tcp", net: "tcp", wantNet: "tcp"},
		{name: "udp", net: "udp", wantNet: "udp"},
		{name: "invalid", net: "unix", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Provider{
				KeyName: "test",
				KeyAlg:  "hmac-sha256",
				Key:     "cWnu6Ju9zOki4f7Q+da2KKGo0KOXbCf6Pej6hW3geC4=",
				Server:  "127.0.0.1:53",
				Net:     tt.net,
			}

			client, err := p.client()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got client with net %q", client.Net)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if client.Net != tt.wantNet {
				t.Fatalf("got net %q, want %q", client.Net, tt.wantNet)
			}
			if client.TsigSecret[p.keyNameFQDN()] != p.Key {
				t.Fatal("tsig secret not configured")
			}
		})
	}
}
