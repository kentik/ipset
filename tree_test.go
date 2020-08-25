package ipset

import (
	"net"
	"testing"

	"github.com/kentik/uint128"
)

func TestNodeFromSet(t *testing.T) {
	parseCidr := func(foo string) *net.IPNet {
		_, net, err := net.ParseCIDR(foo)
		if err != nil {
			panic(err)
		}
		return net
	}

	testCases := []struct {
		desc       string
		cidr       *net.IPNet
		expected   *treeNode
		shouldFail bool
	}{
		{
			desc: "",
			cidr: parseCidr("127.0.0.0/24"),
			expected: &treeNode{
				addr:   uint128.New(0xffff7f000000, 0x0),
				prefix: 120,
			},
		},
		{
			desc: "",
			cidr: parseCidr("255.255.0.0/16"),
			expected: &treeNode{
				addr:   uint128.New(0xffffffff0000, 0x0),
				prefix: 112,
			},
		},
		{
			desc: "",
			cidr: parseCidr("ffff::ffff:ffff/120"),
			expected: &treeNode{
				addr:   uint128.New(0xffffff00, 0xffff000000000000),
				prefix: 120,
			},
		},
		{
			desc: "",
			cidr: parseCidr("ffff:ffff:ffff::ffff:ffff/32"),
			expected: &treeNode{
				addr:   uint128.New(0x0, 0xffffffff00000000),
				prefix: 32,
			},
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			node, err := nodeFromNet(tC.cidr)
			if (err != nil) != tC.shouldFail {
				t.Fatalf("Unexpected error (shouldFail: %t, err: %v)", tC.shouldFail, err)
			}

			if !node.Equals(tC.expected) {
				t.Errorf("Mismatch (expected: %s, got: %s)", tC.expected, node)
			}
		})
	}
}

func TestMatchingPrefix(t *testing.T) {
	testCases := []struct {
		desc   string
		l      uint128.Uint128
		r      uint128.Uint128
		prefix uint32
	}{
		{
			l:      uint128.New(0x00, 0xf000000000000000),
			r:      uint128.New(0x00, 0x8000000000000000),
			prefix: 1,
		},
		{
			l:      uint128.New(0x00, 0xf000000000000000),
			r:      uint128.New(0x00, 0xc000000000000000),
			prefix: 2,
		},
		{
			l:      uint128.New(0x00, 0xf000000000000000),
			r:      uint128.New(0x00, 0xe000000000000000),
			prefix: 3,
		},
		{
			l:      uint128.New(0x00, 0xffff000000000000),
			r:      uint128.New(0x00, 0xff00000000000000),
			prefix: 8,
		},
		{
			l:      uint128.New(0x00, 0x000000000000ffff),
			r:      uint128.New(0x00, 0x000000000000ff00),
			prefix: 56,
		},
		{
			l:      uint128.New(0xf000000000000000, 0x01),
			r:      uint128.New(0x4000000000000000, 0x00),
			prefix: 63,
		},
		{
			l:      uint128.New(0xf000000000000000, 0x00),
			r:      uint128.New(0x4000000000000000, 0x00),
			prefix: 64,
		},
		{
			l:      uint128.New(0xf000000000000000, 0x00),
			r:      uint128.New(0x8000000000000000, 0x00),
			prefix: 65,
		},
		{
			l:      uint128.New(0x00, 0x00),
			r:      uint128.New(0x00, 0x00),
			prefix: 128,
		},
		{
			l:      uint128.New(0x01, 0x00),
			r:      uint128.New(0x00, 0x00),
			prefix: 127,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			matching := matchingPrefix2(tC.l, tC.r)
			if matching != tC.prefix {
				t.Errorf("mismatch (expected: %d, got: %d)", tC.prefix, matching)
			}
		})
	}
}
