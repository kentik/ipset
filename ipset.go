package ipset

import (
	"math/bits"
	"net"
	"strings"
)

// CIDRSet is a fast lookup structure which tells whether ip is covered by any of cidr blocks contained
type CIDRSet interface {
	Contains(net.IP) bool
}

type set struct {
	v4 *treeV4
	v6 *treeV6
}

// NewSet constructs legit set instance
func NewSet(cidrs ...*net.IPNet) CIDRSet {
	s := &set{v4: &treeV4{}, v6: &treeV6{}}
	for _, cidr := range cidrs {
		s.Add(cidr)
	}
	return s
}

func (s *set) Contains(net.IP) bool {
	return false
}

func (s *set) Add(cidr *net.IPNet) {
	if strings.IndexByte(cidr.String(), ':') < 0 {
		s.v4.Add(cidr)
	} else {
		s.v6.Add(cidr)
	}
}

func matchingPrefix(a, b uint32) uint32 {
	return uint32(bits.LeadingZeros32(a ^ b))
}
