package ipset

import (
	"net"
	"testing"
)

func parseCidrs(s ...string) (res []*net.IPNet) {
	for _, ss := range s {
		_, cidr, err := net.ParseCIDR(ss)
		if err != nil {
			panic(err)
		}
		res = append(res, cidr)
	}

	return
}

type test struct {
	arg  net.IP
	want bool
}

var groups = []struct {
	name  string
	cidrs []*net.IPNet
	tests []test
}{
	// {
	// 	name:  "one block enclosing another",
	// 	cidrs: parseCidrs("192.168.0.0/25", "192.168.0.0/24"),
	// 	tests: []test{
	// 		{net.ParseIP("192.168.0.1"), true},
	// 		{net.ParseIP("184.0.0.1"), false},
	// 	},
	// },
	// {
	// 	name:  "two overlapping blocks",
	// 	cidrs: parseCidrs("255.0.0.0/8", "254.0.0.0/8"),
	// 	tests: []test{
	// 		{net.ParseIP("255.0.0.1"), true},
	// 		{net.ParseIP("254.0.0.1"), true},
	// 		{net.ParseIP("253.0.0.1"), false},
	// 	},
	// },
	// {
	// 	name:  "three overlaping blocks",
	// 	cidrs: parseCidrs("255.0.0.0/8", "254.0.0.0/8", "128.0.0.0/8"),
	// 	tests: []test{
	// 		{net.ParseIP("255.0.0.1"), true},
	// 		{net.ParseIP("254.0.0.1"), true},
	// 		{net.ParseIP("253.0.0.1"), false},
	// 		{net.ParseIP("128.0.0.1"), true},
	// 		{net.ParseIP("84.0.0.1"), false},
	// 	},
	// },
	// {
	// 	name:  "2 unrelated /32 blocks",
	// 	cidrs: parseCidrs("127.0.0.1/32", "127.0.0.2/32"),
	// 	tests: []test{
	// 		{net.ParseIP("127.0.0.1"), true},
	// 		{net.ParseIP("127.0.0.2"), true},
	// 		{net.ParseIP("127.0.0.3"), false},
	// 		{net.ParseIP("32.0.0.1"), false},
	// 	},
	// },
	{
		name: "all previous mixed",
		// cidrs: parseCidrs("192.168.0.0/25", "192.168.0.0/24", "255.0.0.0/8", "254.0.0.0/8", "128.0.0.0/8", "127.0.0.1/32", "127.0.0.2/32"),
		cidrs: parseCidrs("192.168.0.0/24", "255.0.0.0/8", "254.0.0.0/8"),
		tests: []test{
			// {net.ParseIP("192.168.0.1"), true},
			// {net.ParseIP("184.0.0.1"), false},
			// {net.ParseIP("255.0.0.1"), true},
			{net.ParseIP("254.0.0.1"), true},
			// {net.ParseIP("253.0.0.1"), false},
			// {net.ParseIP("128.0.0.1"), true},
			// {net.ParseIP("84.0.0.1"), false},
			// {net.ParseIP("127.0.0.1"), true},
			// {net.ParseIP("127.0.0.2"), true},
			// {net.ParseIP("127.0.0.3"), false},
			// {net.ParseIP("32.0.0.1"), false},
		},
	},
	// {
	// 	name:  "0 vs 1 prefix",
	// 	cidrs: parseCidrs("255.0.0.0/8", "128.0.0.0/8"),
	// 	tests: []test{
	// 		{net.ParseIP("255.0.0.1"), true},
	// 		{net.ParseIP("255.0.0.129"), true},
	// 		{net.ParseIP("254.0.0.2"), false},
	// 		{net.ParseIP("254.0.0.129"), false},
	// 		{net.ParseIP("128.0.0.1"), true},
	// 		{net.ParseIP("128.0.0.129"), true},
	// 		{net.ParseIP("129.0.0.2"), false},
	// 		{net.ParseIP("129.0.0.129"), false},
	// 	},
	// },
}

func Test_set_Contains(t *testing.T) {
	for _, group := range groups {
		t.Run(group.name, func(t *testing.T) {
			s := NewSet(group.cidrs...)
			for _, tt := range group.tests {
				t.Run("", func(t *testing.T) {
					if got := s.Contains(tt.arg); got != tt.want {
						t.Errorf("set.Contains() = %v, want %v", got, tt.want)
					}
				})
			}
		})
	}
}
