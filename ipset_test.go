package ipset

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"testing"

	"lukechampine.com/uint128"
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
		name: "de-aggregated multi-prefix policy",
		cidrs: func() []*net.IPNet {
			cidrsCSV := `108.28.248.0/24,108.28.249.0/24,108.28.250.0/24,108.28.251.0/24,113.154.100.0/24,113.154.101.0/24,113.154.102.0/24,113.154.103.0/24,113.154.104.0/24,113.154.105.0/24,113.154.106.0/24,113.154.107.0/24,113.154.108.0/24,113.154.109.0/24,113.154.110.0/24,113.154.111.0/24,113.154.112.0/24,113.154.113.0/24,113.154.114.0/24,113.154.115.0/24,113.154.116.0/24,113.154.117.0/24,113.154.118.0/24,113.154.119.0/24,113.154.120.0/24,113.154.121.0/24,113.154.122.0/24,113.154.123.0/24,113.154.124.0/24,113.154.125.0/24,113.154.127.0/24,113.154.128.0/24,113.154.129.0/24,113.154.130.0/24,113.154.131.0/24,113.154.132.0/24,113.154.133.0/24,113.154.134.0/24,113.154.135.0/24,113.154.136.0/24,113.154.137.0/24,113.154.138.0/24,113.154.139.0/24,113.154.140.0/24,113.154.141.0/24,113.154.142.0/24,113.154.143.0/24,113.154.144.0/24,113.154.145.0/24,113.154.146.0/24,113.154.147.0/24,113.154.148.0/24,113.154.149.0/24,113.154.150.0/24,113.154.151.0/24,113.154.152.0/24,113.154.153.0/24,113.154.154.0/24,113.154.155.0/24,113.154.156.0/24,113.154.157.0/24,113.154.158.0/24,113.154.159.0/24,113.154.160.0/24,113.154.161.0/24,113.154.162.0/24,113.154.163.0/24,113.154.164.0/24,113.154.165.0/24,113.154.166.0/24,113.154.167.0/24,113.154.168.0/24,113.154.169.0/24,113.154.170.0/24,113.154.171.0/24,113.154.172.0/24,113.154.173.0/24,113.154.174.0/24,113.154.175.0/24,113.154.176.0/24,113.154.177.0/24,113.154.178.0/24,113.154.179.0/24,113.154.180.0/24,113.154.181.0/24,113.154.182.0/24,113.154.183.0/24,113.154.184.0/24,113.154.185.0/24,113.154.189.0/24,113.154.192.0/24,113.154.193.0/24,113.154.194.0/24,113.154.195.0/24,113.154.196.0/24,113.154.197.0/24,113.154.199.0/24,113.154.200.0/24,113.154.201.0/24,113.154.202.0/24,113.154.205.0/24,113.154.206.0/24,113.154.207.0/24,113.154.208.0/24,113.154.209.0/24,113.154.210.0/24,113.154.212.0/24,113.154.213.0/24,113.154.214.0/24,113.154.215.0/24,113.154.216.0/24,113.154.217.0/24,113.154.218.0/24,113.154.219.0/24,113.154.220.0/24,113.154.221.0/24,113.154.224.0/24,113.154.225.0/24,113.154.226.0/24,113.154.227.0/24,113.154.228.0/24,113.154.229.0/24,113.154.230.0/24,113.154.231.0/24,113.154.232.0/24,113.154.233.0/24,113.154.234.0/24,113.154.235.0/24,113.154.236.0/24,113.154.237.0/24,113.154.238.0/24,113.154.239.0/24,113.154.240.0/24,113.154.241.0/24,113.154.242.0/24,113.154.243.0/24,113.154.244.0/24,113.154.245.0/24,113.154.246.0/24,113.154.247.0/24,113.154.248.0/24,113.154.249.0/24,113.154.251.0/24,113.154.36.0/24,113.154.37.0/24,113.154.38.0/24,113.154.39.0/24,113.154.60.0/24,113.154.61.0/24,113.154.62.0/24,113.154.63.0/24,113.154.65.0/24,113.154.66.0/24,113.154.70.0/24,113.154.71.0/24,113.154.72.0/24,113.154.73.0/24,113.154.75.0/24,113.154.76.0/24,113.154.77.0/24,113.154.79.0/24,113.154.80.0/24,113.154.81.0/24,113.154.82.0/24,113.154.83.0/24,113.154.84.0/24,113.154.85.0/24,113.154.86.0/24,142.126.72.0/24,142.126.73.0/24,142.126.74.0/24,142.126.77.0/24,142.126.79.0/24,186.11.124.0/24,186.11.125.0/24,190.230.100.0/24,190.230.101.0/24,190.230.102.0/24,190.230.108.0/24,190.230.109.0/24,190.230.110.0/24,190.230.112.0/24,190.230.116.0/24,190.230.117.0/24,190.230.118.0/24,190.230.119.0/24,190.230.124.0/24,190.230.64.0/24,190.230.65.0/24,190.230.66.0/24,190.230.67.0/24,190.230.68.0/24,190.230.69.0/24,190.230.70.0/24,190.230.74.0/24,190.230.77.0/24,190.230.78.0/24,190.230.79.0/24,190.230.80.0/24,190.230.81.0/24,190.230.82.0/24,190.230.83.0/24,190.230.84.0/24,190.230.85.0/24,190.230.91.0/24,190.230.92.0/24,190.230.93.0/24,190.230.95.0/24,190.230.96.0/24,201.143.50.0/24,201.143.59.0/24,202.83.128.0/24,202.83.129.0/24,202.83.130.0/24,202.83.131.0/24,202.83.132.0/24,202.83.133.0/24,202.83.134.0/24,202.83.135.0/24,42.223.16.0/24,42.223.17.0/24,42.223.18.0/24,42.223.19.0/24,42.223.20.0/24,42.223.21.0/24,42.223.22.0/24,42.223.23.0/24,42.223.24.0/24,42.223.25.0/24,42.223.26.0/24,42.223.27.0/24,42.223.28.0/24,42.223.29.0/24,42.223.30.0/24,42.223.31.0/24,42.223.32.0/24,42.223.33.0/24,42.223.34.0/24,42.223.35.0/24,42.223.36.0/24,42.223.37.0/24,42.223.38.0/24,42.223.39.0/24,42.223.40.0/24,42.60.0.0/24,42.60.1.0/24,42.60.10.0/24,42.60.100.0/24,42.60.101.0/24,42.60.102.0/24,42.60.103.0/24,42.60.104.0/24,42.60.105.0/24,42.60.106.0/24,42.60.107.0/24,42.60.108.0/24,42.60.109.0/24,42.60.11.0/24,42.60.110.0/24,42.60.111.0/24,42.60.112.0/24,42.60.113.0/24,42.60.114.0/24,42.60.115.0/24,42.60.116.0/24,42.60.117.0/24,42.60.118.0/24,42.60.119.0/24,42.60.12.0/24,42.60.120.0/24,42.60.121.0/24,42.60.122.0/24,42.60.123.0/24,42.60.124.0/24,42.60.125.0/24,42.60.126.0/24,42.60.127.0/24,42.60.128.0/24,42.60.129.0/24,42.60.13.0/24,42.60.130.0/24,42.60.131.0/24,42.60.132.0/24,42.60.133.0/24,42.60.134.0/24,42.60.135.0/24,42.60.136.0/24,42.60.137.0/24,42.60.138.0/24,42.60.139.0/24,42.60.14.0/24,42.60.140.0/24,42.60.141.0/24,42.60.142.0/24,42.60.143.0/24,42.60.144.0/24,42.60.145.0/24,42.60.146.0/24,42.60.147.0/24,42.60.148.0/24,42.60.149.0/24,42.60.15.0/24,42.60.150.0/24,42.60.151.0/24,42.60.152.0/24,42.60.153.0/24,42.60.154.0/24,42.60.155.0/24,42.60.156.0/24,42.60.157.0/24,42.60.158.0/24,42.60.159.0/24,42.60.16.0/24,42.60.160.0/24,42.60.161.0/24,42.60.162.0/24,42.60.163.0/24,42.60.164.0/24,42.60.165.0/24,42.60.166.0/24,42.60.167.0/24,42.60.168.0/24,42.60.169.0/24,42.60.17.0/24,42.60.170.0/24,42.60.171.0/24,42.60.172.0/24,42.60.175.0/24,42.60.176.0/24,42.60.177.0/24,42.60.18.0/24,42.60.181.0/24,42.60.182.0/24,42.60.183.0/24,42.60.184.0/24,42.60.188.0/24,42.60.19.0/24,42.60.195.0/24,42.60.196.0/24,42.60.197.0/24,42.60.198.0/24,42.60.199.0/24,42.60.20.0/24,42.60.200.0/24,42.60.201.0/24,42.60.202.0/24,42.60.203.0/24,42.60.204.0/24,42.60.205.0/24,42.60.206.0/24,42.60.21.0/24,42.60.211.0/24,42.60.212.0/24,42.60.213.0/24,42.60.214.0/24,42.60.215.0/24,42.60.216.0/24,42.60.217.0/24,42.60.218.0/24,42.60.219.0/24,42.60.22.0/24,42.60.220.0/24,42.60.221.0/24,42.60.222.0/24,42.60.223.0/24,42.60.23.0/24,42.60.232.0/24,42.60.233.0/24,42.60.24.0/24,42.60.25.0/24,42.60.26.0/24,42.60.27.0/24,42.60.28.0/24,42.60.29.0/24,42.60.3.0/24,42.60.30.0/24,42.60.31.0/24,42.60.32.0/24,42.60.33.0/24,42.60.34.0/24,42.60.35.0/24,42.60.36.0/24,42.60.37.0/24,42.60.38.0/24,42.60.39.0/24,42.60.4.0/24,42.60.40.0/24,42.60.41.0/24,42.60.43.0/24,42.60.44.0/24,42.60.45.0/24,42.60.46.0/24,42.60.47.0/24,42.60.48.0/24,42.60.49.0/24,42.60.5.0/24,42.60.50.0/24,42.60.51.0/24,42.60.52.0/24,42.60.53.0/24,42.60.54.0/24,42.60.55.0/24,42.60.56.0/24,42.60.57.0/24,42.60.58.0/24,42.60.59.0/24,42.60.6.0/24,42.60.62.0/24,42.60.63.0/24,42.60.64.0/24,42.60.65.0/24,42.60.66.0/24,42.60.67.0/24,42.60.68.0/24,42.60.69.0/24,42.60.7.0/24,42.60.70.0/24,42.60.71.0/24,42.60.72.0/24,42.60.73.0/24,42.60.74.0/24,42.60.75.0/24,42.60.76.0/24,42.60.77.0/24,42.60.78.0/24,42.60.79.0/24,42.60.8.0/24,42.60.80.0/24,42.60.81.0/24,42.60.82.0/24,42.60.83.0/24,42.60.84.0/24,42.60.85.0/24,42.60.86.0/24,42.60.87.0/24,42.60.88.0/24,42.60.89.0/24,42.60.9.0/24,42.60.90.0/24,42.60.91.0/24,42.60.92.0/24,42.60.93.0/24,42.60.94.0/24,42.60.95.0/24,42.60.96.0/24,42.60.97.0/24,42.60.98.0/24,42.60.99.0/24,42.64.64.0/24,42.64.65.0/24,42.64.66.0/24,42.64.67.0/24`
			cidrsRaw := strings.Split(cidrsCSV, ",")
			return parseCidrs(cidrsRaw...)
		}(),
		negativeIPs: []net.IP{
			net.ParseIP("0.0.0.0"),
			net.ParseIP("1.2.3.4"),
			net.ParseIP("42.59.255.255"), // last ip before min int value from lowest block (708575232-1 = 708575231)
			net.ParseIP("202.83.136.0"),  // last ip after max+255+1 int value from highest block (3394471680 + 255 + 1 = 3394471936)
			net.ParseIP("203.204.205.206"),
			net.ParseIP("255.255.255.255"),
		},
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
