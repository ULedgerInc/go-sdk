package transaction

import "testing"

func TestValidateEntityName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"acme-org", true},
		{"alice-agent", true},
		{"a1b2", true},
		{"abc", true},
		{"Acme-Org", true},   // capitals normalized to lowercase
		{"  acme-org  ", true}, // surrounding whitespace trimmed
		{"Acme Org", false},  // internal space rejected
		{"ab", false},        // too short (min 3)
		{"-acme", false},     // cannot start with hyphen
		{"acme-", false},     // cannot end with hyphen
		{"acme_org", false},  // underscore not allowed
		{"", false},
	}
	for _, c := range cases {
		if got := ValidateEntityName(c.name); got != c.want {
			t.Errorf("ValidateEntityName(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}
