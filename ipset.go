package ipset

import (
	"fmt"
	"math/bits"
	"net"
	"strings"

	"github.com/kentik/chf-alert/pkg/alert/util"
)

// CIDRSet is a fast lookup structure which tells whether ip is covered by any of cidr blocks contained
type CIDRSet interface {
	Contains(net.IP) bool
	ContainsRawIPv4(uint32) bool
}

type set struct {
	v4 *treeV4
	v6 *treeV6
}

// NewSet constructs set from list of cidrs
func NewSet(cidrs ...*net.IPNet) CIDRSet {
	s := &set{v4: &treeV4{}, v6: &treeV6{}}
	for _, cidr := range cidrs {
		s.Add(cidr)
	}
	return s
}

// NewSetFromCSV constructs set from comma separated list of cidrs
func NewSetFromCSV(cidrsCSV string) (CIDRSet, error) {
	cidrs, err := util.IPCidrListFromRaw(cidrsCSV)
	if err != nil {
		return nil, fmt.Errorf("from NewSetFromCSV: %w", err)
	}

	return NewSet(cidrs...), nil
}

func (s *set) Contains(ip net.IP) bool {
	if strings.IndexByte(ip.String(), ':') < 0 {
		return s.v4.Contains(ip)
	}
	return s.v6.Contains(ip)
}

func (s *set) ContainsRawIPv4(ip uint32) bool {
	return s.v4.ContainsRaw(ip)
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
