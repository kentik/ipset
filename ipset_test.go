package ipset

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/kentik/chf-alert/pkg/alert/util"
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
		name: "***REMOVED***",
		cidrs: func() []*net.IPNet {
			cidrsCSV := `***REMOVED***`
			cidrsRaw := strings.Split(cidrsCSV, ",")
			return parseCidrs(cidrsRaw...)
		}(),
		negativeIPs: []net.IP{
			net.ParseIP("0.0.0.0"),
			net.ParseIP("1.2.3.4"),
			net.ParseIP("***REMOVED***"), // last ip before min int value from ***REMOVED***"***REMOVED***"),  // last ip after max+255+1 int value from ***REMOVED***"***REMOVED***"),
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
			s := NewSet2(group.cidrs...)

			for _, ip := range group.negativeIPs {
				t.Run(ip.String(), func(t *testing.T) {
					if got := s.Contains(ip); got != false {
						t.Errorf("negative case returned true: %s", ip.String())
					}
				})
			}

			for _, cidr := range group.cidrs {
				low, high, err := util.GetHostsRangeFromCIDR(cidr.String())
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
