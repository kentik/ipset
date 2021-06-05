package ipset

import (
	"encoding/binary"
	"net"
	"strings"
	"strconv"
	"testing"

	"github.com/kentik/uint128"
)

func parseCidrs(s ...string) (res []*net.IPNet) {
	res = make([]*net.IPNet, len(s))
	for i, ss := range s {
		_, cidr, err := net.ParseCIDR(ss)
		if err != nil {
			panic(err)
		}
		res[i] = cidr
	}

	return
}

// TODO(tjonak): those tests add 1.5s to chf-alert test suite, move this to separate package
var groups = []struct {
	name        string
	cidrs       []*net.IPNet
	negativeIPs []net.IP
}{
	{
		name:        "one block enclosing another",
		cidrs:       parseCidrs("192.168.0.0/25", "192.168.0.0/24"),
		negativeIPs: []net.IP{net.ParseIP("184.0.0.1")},
	},
	{
		name:        "two overlapping blocks",
		cidrs:       parseCidrs("255.0.0.0/20", "254.0.0.0/20"),
		negativeIPs: []net.IP{net.ParseIP("253.0.0.1")},
	},
	{
		name:        "three overlaping blocks",
		cidrs:       parseCidrs("255.0.0.0/20", "254.0.0.0/20", "128.0.0.0/20"),
		negativeIPs: []net.IP{net.ParseIP("253.0.0.1"), net.ParseIP("84.0.0.1")},
	},
	{
		name:        "2 unrelated /32 blocks",
		cidrs:       parseCidrs("127.0.0.1/32", "127.0.0.2/32"),
		negativeIPs: []net.IP{net.ParseIP("127.0.0.3"), net.ParseIP("32.0.0.1")},
	},
	{
		name:        "all previous mixed",
		cidrs:       parseCidrs("192.168.0.0/25", "192.168.0.0/24", "255.0.0.0/20", "254.0.0.0/20", "128.0.0.0/20", "127.0.0.1/32", "127.0.0.2/32"),
		negativeIPs: []net.IP{net.ParseIP("184.0.0.1"), net.ParseIP("253.0.0.1"), net.ParseIP("84.0.0.1"), net.ParseIP("127.0.0.3"), net.ParseIP("32.0.0.1")},
	},
	{
		name:        "0 vs 1 prefix",
		cidrs:       parseCidrs("255.0.0.0/20", "128.0.0.0/20"),
		negativeIPs: []net.IP{net.ParseIP("254.0.0.2"), net.ParseIP("254.0.0.129"), net.ParseIP("129.0.0.2"), net.ParseIP("129.0.0.129")},
	},
	{
		name:  "panic from tests1",
		cidrs: parseCidrs("172.17.0.0/24", "172.17.0.1/24"),
		negativeIPs: []net.IP{
			net.IP([]byte{32, 1, 5, 160, 13, 0, 0, 0, 0, 0, 0, 0, 66, 110, 0, 24}),
		},
	},
	{
		name:        "matching => node.prefix && node.prefix < offset",
		cidrs:       parseCidrs("255.255.255.0/24", "255.255.240.0/20"),
		negativeIPs: []net.IP{net.ParseIP("254.0.0.2")},
	},
	{
		name:  "two disjoint ipv4 blocks",
		cidrs: parseCidrs("192.168.0.0/24", "255.0.0.0/20"),
	},
}

func TestSetContains(t *testing.T) {
	for _, group := range groups {
		t.Run(group.name, func(t *testing.T) {
			s := NewSet(group.cidrs...)

			for _, ip := range group.negativeIPs {
				t.Run(ip.String(), func(t *testing.T) {
					if got := s.Contains(ip); got != false {
						t.Errorf("negative case returned true: %s", ip.String())
					}
				})
			}

			for _, cidr := range group.cidrs {
				low, high, err := getHostsRangeFromCIDR(cidr.String())
				if err != nil {
					t.Fatalf("Getting cidr range failed: %v", err)
				}

				for i := uint64(low); i <= uint64(high); i++ {
					ip := make(net.IP, 4)
					binary.BigEndian.PutUint32(ip, uint32(i))
					t.Run(ip.String(), func(t *testing.T) {
						got := s.Contains(ip)
						if got != true {
							t.Errorf("positive case returned false: %s", ip.String())
						}
					})
				}
			}
		})
	}
}

var ipv6Groups = []struct {
	name        string
	cidrs       []*net.IPNet
	positiveIPs []net.IP
	negativeIPs []net.IP
}{
	{
		name:        "two disjoint blocks",
		cidrs:       parseCidrs("0001::/32", "fff1::/32"),
		positiveIPs: []net.IP{net.ParseIP("0001::2"), net.ParseIP("fff1::2")},
		negativeIPs: []net.IP{net.ParseIP("254.0.0.2"), net.ParseIP("fff2::")},
	},
}

func TestSetContainsIPv6(t *testing.T) {
	for _, group := range ipv6Groups {
		t.Run(group.name, func(t *testing.T) {
			s := NewSet(group.cidrs...)

			for _, ip := range group.negativeIPs {
				t.Run(ip.String(), func(t *testing.T) {
					if got := s.Contains(ip); got != false {
						t.Errorf("negative case returned true: %s", ip.String())
					}
				})
			}

			for _, ip := range group.positiveIPs {
				t.Run(ip.String(), func(t *testing.T) {
					if got := s.Contains(ip); got != true {
						t.Errorf("positive case returned true: %s", ip.String())
					}
				})
			}

			for _, cidr := range group.cidrs {
				t.Run(cidr.IP.String(), func(t *testing.T) {
					got := s.Contains(cidr.IP)
					if got != true {
						t.Errorf("cidr case returned false: %s", cidr.IP.String())
					}
				})
			}
		})
	}
}

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
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			node, err := nodeFromNet(tc.cidr)
			if (err != nil) != tc.shouldFail {
				t.Fatalf("Unexpected error (shouldFail: %t, err: %v)", tc.shouldFail, err)
			}

			if !node.Equals(tc.expected) {
				t.Errorf("Mismatch (expected: %s, got: %s)", tc.expected, node)
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
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			matching := matchingPrefix(tc.l, tc.r)
			if matching != tc.prefix {
				t.Errorf("mismatch (expected: %d, got: %d)", tc.prefix, matching)
			}
		})
	}
}

func getHostsRangeFromCIDR(s string) (uint32, uint32, error) {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return 0, 0, err
	}
	low, high := getHostsRangeFromIPNet(ipnet)
	return low, high, nil
}

func getHostsRangeFromIPNet(ipnet *net.IPNet) (uint32, uint32) {
	itval := inetAtoN(ipnet.IP)
	mask := strings.Split(ipnet.String(), "/")[1]
	return getHostsRange(mask, itval)
}

func getHostsRange(netmask string, numeric_ipv4 uint32) (uint32, uint32) {
	nmi, err := strconv.Atoi(netmask)
	nm := uint32(nmi)

	if err != nil || nm > 32 {
		return 0, 0
	}

	bitmask := uint32(0xFFFFFFFF)
	subnet := uint32(32 - nm)

	bitmask = bitmask >> subnet
	bitmask = bitmask << subnet

	return numeric_ipv4 & bitmask, numeric_ipv4 | ^bitmask
}

func inetAtoN(ipnr net.IP) uint32 {
	bits := strings.Split(ipnr.String(), ".")

	b0, _ := strconv.Atoi(bits[0])
	b1, _ := strconv.Atoi(bits[1])
	b2, _ := strconv.Atoi(bits[2])
	b3, _ := strconv.Atoi(bits[3])

	var sum uint32

	sum += uint32(b0) << 24
	sum += uint32(b1) << 16
	sum += uint32(b2) << 8
	sum += uint32(b3)

	return sum
}
