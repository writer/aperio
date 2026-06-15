package syncwake

import "testing"

func TestEncodeDecode(t *testing.T) {
	tests := []struct {
		name        string
		payload     string
		wantID      string
		wantStream  string
		encodedFrom []string
	}{
		{name: "legacy id", payload: "  int_123  ", wantID: "int_123"},
		{name: "stream payload", payload: "int_123\tdrive", wantID: "int_123", wantStream: "drive"},
		{name: "encoded stream", wantID: "int_123", wantStream: "admin", encodedFrom: []string{" int_123 ", " admin "}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := tt.payload
			if len(tt.encodedFrom) == 2 {
				payload = Encode(tt.encodedFrom[0], tt.encodedFrom[1])
			}
			gotID, gotStream := Decode(payload)
			if gotID != tt.wantID || gotStream != tt.wantStream {
				t.Fatalf("Decode(%q)=(%q,%q), want (%q,%q)", payload, gotID, gotStream, tt.wantID, tt.wantStream)
			}
		})
	}
}
