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
	{
		cidrs: parseCidrs("192.168.0.0/25", "192.168.0.0/24"),
		tests: []test{
			{net.ParseIP("192.168.0.1"), true},
			{net.ParseIP("255.0.0.1"), false},
		},
	},
	{
		cidrs: parseCidrs("255.0.0.0/8", "254.0.0.0/8"),
		tests: []test{
			{net.ParseIP("255.0.0.1"), true},
		},
	},
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
