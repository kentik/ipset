package ipset

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/kentik/uint128"
)

type treeNode struct {
	addr   uint128.Uint128
	prefix uint32
	left   *treeNode
	right  *treeNode
}

func (n *treeNode) String() string {
	return fmt.Sprintf("%s:%d", n.addr, n.prefix)
}

func (n *treeNode) Equals(node *treeNode) bool {
	if node == nil {
		return false
	}

	return n.addr.Equals(node.addr) && n.prefix == node.prefix
}

type uint128set struct {
	root *treeNode
}

func (s *uint128set) ContainsRawIPv4(ipRaw uint32) bool {
	ipByte := make([]byte, 4)
	binary.BigEndian.PutUint32(ipByte, ipRaw)
	ip := net.IP(ipByte)
	return s.Contains(ip)
}

func NewSet2(cidrs ...*net.IPNet) CIDRSet {
	set := &uint128set{}

	for _, cidr := range cidrs {
		set.Add(cidr)
	}

	return set
}

func uint128FromIP(ip net.IP) (uint128.Uint128, error) {
	ipv6 := ip.To16()
	if ipv6 == nil {
		return uint128.Zero, fmt.Errorf("invalid ip provided: %v", []byte(ip))
	}

	return uint128.New(binary.BigEndian.Uint64(ipv6[8:]), binary.BigEndian.Uint64(ipv6[:8])), nil
}

func nodeFromNet(cidr *net.IPNet) (*treeNode, error) {
	if cidr == nil {
		return nil, fmt.Errorf("nil node passed")
	}

	addr, err := uint128FromIP(cidr.IP)
	if err != nil {
		return nil, err
	}

	prefixLen, size := cidr.Mask.Size()
	if size < 128 {
		// ipv4, translate to ipv6 mask
		// 0x0000000000ffff - static prefix used in ipv6 mapped ipv4 addrs, len = 96
		// 96 + prefixLen = ipv6 subnet mask
		prefixLen += 96
	}

	return &treeNode{addr: addr, prefix: uint32(prefixLen)}, nil
}

func (s *uint128set) Add(cidr *net.IPNet) {
	node, err := nodeFromNet(cidr)
	if err != nil {
		panic(err)
	}

	if s.root == nil {
		s.root = node
		return
	}

	curr := s.root
	offset := uint32(0)
	for {
		matching := matchingPrefix2(node.addr, curr.addr)
		offset += curr.prefix

		if matching < node.prefix && matching < offset {
			// three way split
			newNode := &treeNode{
				addr:   node.addr,
				prefix: node.prefix - matching,
			}
			splittedNode := &treeNode{
				addr:   curr.addr,
				prefix: offset - matching,
				left:   curr.left,
				right:  curr.right,
			}

			if curr.addr.Rsh(uint(128-(matching+1))).And64(0x01) == uint128.Zero {
				curr.left, curr.right = splittedNode, newNode
			} else {
				curr.left, curr.right = newNode, splittedNode
			}

			curr.prefix += matching - offset

			return
		}

		// incoming subnet has shorter prefix, discard remaining parts of the tree
		if matching >= node.prefix && node.prefix < offset {
			curr.prefix += node.prefix - offset
			curr.left, curr.right = nil, nil
			return
		}

		if curr.left == nil {
			// currently stored prefix is shorter than new one
			// so new subnet is enclosed by existing subnet address space, nothing to do
			return
		}

		// we are still traversing through prefix, decide which route next
		if (node.addr.Rsh(uint(128 - (offset + 1)))).And64(0x01) == uint128.Zero {
			curr = curr.left
		} else {
			curr = curr.right
		}
	}
}

func matchingPrefix2(l, r uint128.Uint128) uint32 {
	return uint32(l.Xor(r).LeadingZeros())
}

func (s *uint128set) Contains(ip net.IP) bool {
	if s.root == nil {
		return false
	}

	addr, err := uint128FromIP(ip)
	if err != nil {
		return false
	}

	curr := s.root
	offset := uint32(0)
	for {
		matching := matchingPrefix2(addr, curr.addr)
		offset += curr.prefix
		if matching < offset {
			return false
		}

		if curr.left == nil || matching == 128 {
			return true
		}

		if addr.Rsh(uint(128-(offset+1))).And64(0x01) == uint128.Zero {
			curr = curr.left
		} else {
			curr = curr.right
		}
	}
}
