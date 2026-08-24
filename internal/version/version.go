// Package version holds the build-stamped version of the running binary and
// defines an ordering over version strings.
//
// The ordering is a small subset of semver rather than a dependency. An updater
// is a poor place to inherit somebody else's supply chain, so this repository
// uses only the standard library.
package version

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is stamped at link time:
//
//	go build -ldflags "-X .../internal/version.Version=1.2.3"
//
// The default marks a working-tree build and sorts below every real release, so
// a development binary always accepts an update.
var Version = "0.0.0-dev"

// semver is MAJOR.MINOR.PATCH with an optional pre-release tag.
type semver struct {
	major, minor, patch int
	pre                 string // empty means a final release
}

// Parse reads a version string. A leading "v" and any build metadata are
// accepted and ignored, since neither affects ordering.
func Parse(s string) (semver, error) {
	var v semver

	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		v.pre, s = s[i+1:], s[:i]
	}

	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, fmt.Errorf("version %q: want MAJOR.MINOR.PATCH", s)
	}
	into := [...]*int{&v.major, &v.minor, &v.patch}
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return v, fmt.Errorf("version %q: bad component %q", s, part)
		}
		*into[i] = n
	}
	return v, nil
}

// Valid reports whether s can be ordered.
func Valid(s string) bool {
	_, err := Parse(s)
	return err == nil
}

// Compare returns -1 if a sorts before b, 0 if they are equal, +1 otherwise.
//
// A pre-release sorts before its final release, which is what puts "0.0.0-dev"
// below everything. An unparseable version sorts below a parseable one: a
// corrupt local version can still be updated away from, but a corrupt remote
// version can never look newer than what is installed.
func Compare(a, b string) int {
	va, errA := Parse(a)
	vb, errB := Parse(b)

	switch {
	case errA != nil && errB != nil:
		return strings.Compare(a, b)
	case errA != nil:
		return -1
	case errB != nil:
		return 1
	}

	for _, delta := range [...]int{va.major - vb.major, va.minor - vb.minor, va.patch - vb.patch} {
		if delta != 0 {
			return sign(delta)
		}
	}
	return comparePre(va.pre, vb.pre)
}

// Newer reports whether a sorts strictly after b.
func Newer(a, b string) bool { return Compare(a, b) > 0 }

// Older reports whether a sorts strictly before b.
func Older(a, b string) bool { return Compare(a, b) < 0 }

func comparePre(a, b string) int {
	switch {
	case a == b:
		return 0
	case a == "": // a is a final release, b is a pre-release of it
		return 1
	case b == "":
		return -1
	}
	return strings.Compare(a, b)
}

func sign(n int) int {
	if n < 0 {
		return -1
	}
	return 1
}
