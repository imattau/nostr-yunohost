package main

import "testing"

func TestDefaultMinimumEndorsements(t *testing.T) {
	tests := []struct {
		name  string
		raw   string
		value int
	}{
		{name: "unset", raw: "", value: 1},
		{name: "valid", raw: "3", value: 3},
		{name: "zero", raw: "0", value: 1},
		{name: "negative", raw: "-2", value: 1},
		{name: "invalid", raw: "not-a-number", value: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("NOSTR_YNH_MINIMUM_ENDORSEMENTS", test.raw)
			if got := defaultMinimumEndorsements(); got != test.value {
				t.Fatalf("defaultMinimumEndorsements() = %d, want %d", got, test.value)
			}
		})
	}
}
