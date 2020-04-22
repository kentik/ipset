package ipset

import (
	"encoding/binary"
	"fmt"
	"net"
)

type treeNodeV4 struct {
	addr        uint32
	prefix      uint32
	left, right uint
}

func nodeV4FromCIDR(c cidrV4) treeNodeV4 {
	return treeNodeV4{
		addr:   c.addr,
		prefix: c.prefix,
	}
}

type cidrV4 struct {
	addr   uint32
	prefix uint32 // really length of prefix, no reason in keeping bits
}

func cidrV4FromNet(cidr *net.IPNet) cidrV4 {
	ipv4 := cidr.IP.To4()
	if ipv4 == nil {
		panic(fmt.Sprintf("non ipv4 addr %v", cidr.IP))
	}

	size, _ := cidr.Mask.Size()

	return cidrV4{
		addr:   binary.BigEndian.Uint32(ipv4),
		prefix: uint32(size),
	}
}

type treeV4 struct {
	nodes     []treeNodeV4
	freeNodes []uint
}

func (t *treeV4) getFreeNode() uint {
	if (len(t.freeNodes) + cap(t.nodes)) < (len(t.nodes) + 10) {
		temp := make([]treeNodeV4, len(t.nodes), (cap(t.nodes)+1)*2)
		copy(temp, t.nodes)
		t.nodes = temp
	}

	idx := t.freeNodes[0]
	t.freeNodes = t.freeNodes[1:]
	return idx
}

func (t *treeV4) freeUpNodes(idxs ...uint) {
	for {
		if len(idxs) == 0 {
			return
		}
		cur := idxs[0]
		idxs = idxs[1:]

		if cur == 0 {
			continue
		}

		node := &t.nodes[cur]
		if node.left != 0 {
			idxs = append(idxs, node.left)
		}

		if node.right != 0 {
			idxs = append(idxs, node.right)
		}

		t.nodes[cur] = treeNodeV4{}
		t.freeNodes = append(t.freeNodes, cur)
	}
}

func (t *treeV4) Add(cidr *net.IPNet) {
	cdr := cidrV4FromNet(cidr)

	if len(t.nodes) == 0 {
		t.nodes = append(t.nodes, nodeV4FromCIDR(cdr))
		return
	}

	curr := &t.nodes[0]
	offset := uint32(0)
	for {
		matching := matchingPrefix(curr.addr, cdr.addr)
		// current cidr contains added one, nothing to do
		if matching >= curr.prefix && cdr.prefix >= curr.prefix && curr.left == 0 && curr.right == 0 {
			return
		}

		// incoming cidr has shorter prefix, discard remaining parts of the tree
		if matching >= curr.prefix && cdr.prefix < curr.prefix {
			curr.prefix = cdr.prefix
			t.freeUpNodes(curr.left, curr.right)
			curr.left, curr.right = 0, 0
			return
		}

		if matching <= curr.prefix && matching == cdr.prefix {
			// three way split
		}

		if curr.left == 0 {
			idx := len(t.nodes)
			t.nodes = append(t.nodes, treeNodeV4{
				addr:   cdr.addr,
				prefix: cdr.prefix - offset - curr.prefix,
			})
			curr.left = uint(idx)
		}

		curr = &t.nodes[curr.left]
	}

	return
}
