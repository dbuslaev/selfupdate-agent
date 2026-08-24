package version

import "testing"

func TestCompareOrdersVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.1.0", "1.0.9", 1},
		{"2.0.0", "1.99.99", 1},
		{"1.10.0", "1.9.0", 1}, // numeric, not lexical
		{"v1.2.3", "1.2.3", 0}, // a leading v is cosmetic
		{"1.2.3+build7", "1.2.3", 0},
		{"1.2.0-rc1", "1.2.0", -1}, // a pre-release precedes its release
		{"1.2.0-rc1", "1.2.0-rc2", -1},
		{"0.0.0-dev", "0.0.1", -1}, // a dev build always accepts an update
		{"0.0.0-dev", "0.0.0", -1},
		{"garbage", "1.0.0", -1}, // unparseable never looks newer
		{"1.0", "1.0.0", -1},     // wrong arity is unparseable
	}

	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := Compare(c.b, c.a); got != -c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}

func TestValid(t *testing.T) {
	for _, s := range []string{"1.0.0", "v0.1.2", "1.2.3-rc1", "10.20.30"} {
		if !Valid(s) {
			t.Errorf("Valid(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "1", "1.0", "1.0.0.0", "a.b.c", "-1.0.0", "1.0.x"} {
		if Valid(s) {
			t.Errorf("Valid(%q) = true, want false", s)
		}
	}
}

func TestNewerAndOlder(t *testing.T) {
	if !Newer("1.1.0", "1.0.0") || Newer("1.0.0", "1.1.0") || Newer("1.0.0", "1.0.0") {
		t.Error("Newer is wrong")
	}
	if !Older("1.0.0", "1.1.0") || Older("1.1.0", "1.0.0") || Older("1.0.0", "1.0.0") {
		t.Error("Older is wrong")
	}
}
