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

func (t *treeV4) ensureCapacity() {
	if len(t.freeNodes) > 10 {
		return
	}

	temp := make([]treeNodeV4, (len(t.nodes)+1)*2)
	copy(temp, t.nodes)

	for i := len(t.nodes); i < len(temp); i++ {
		t.freeNodes = append(t.freeNodes, uint(i))
	}

	t.nodes = temp
}

func (t *treeV4) getFreeNode() uint {
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
	t.ensureCapacity()

	curr := &t.nodes[0]
	offset := uint32(0)
	for {
		matching := matchingPrefix(curr.addr, cdr.addr)

		if offset > cdr.prefix {
			panic("think about this case")
		}

		if matching >= offset+curr.prefix && matching < cdr.prefix {
			// decide whether to branch left or right
			// left and right are always set together, might as well check just one
			if curr.left == 0 {
				// currently stored prefix is shorter than new one
				// so new cidr is enclosed by existing cidr address space, nothing to do
				return
			}

			// current pattern is exhausted decide whether to go left or right based on msb after offset+curr.prefix
			// memorize offset
			offset += curr.prefix
			if (cdr.addr>>(32-(matching+1)))&0x1 == 0 {
				curr = &t.nodes[curr.left]
			} else {
				curr = &t.nodes[curr.right]
			}
			// look at next candidate
			// TODO(tjonak): what if we traversed to 32 bit boundary

			continue
		}

		// incoming cidr has shorter prefix, discard remaining parts of the tree
		if matching >= curr.prefix && cdr.prefix < offset+curr.prefix {
			curr.prefix = cdr.prefix - offset
			t.freeUpNodes(curr.left, curr.right)
			curr.left, curr.right = 0, 0
			return
		}

		if matching < offset+curr.prefix && matching < cdr.prefix {
			// three way split
			newIDX := t.getFreeNode()
			new := &t.nodes[newIDX]
			splittedIDX := t.getFreeNode()
			splitted := &t.nodes[splittedIDX]

			splitted.left = curr.left
			splitted.right = curr.right

			// peek at first non-matching bit and decide which branch is which
			if (curr.addr>>(32-(matching+1)))&0x1 == 0 {
				curr.left, curr.right = splittedIDX, newIDX
			} else {
				curr.left, curr.right = newIDX, splittedIDX
			}

			new.addr = cdr.addr
			new.prefix = cdr.prefix - matching

			splitted.addr = curr.addr
			splitted.prefix = curr.prefix + offset - matching

			curr.prefix = matching - offset

			return
		}

		panic(fmt.Sprintf("%d, %x %d, %x %d", offset, curr.addr, curr.prefix, cdr.addr, cdr.prefix))
	}
}

func (t *treeV4) Contains(ip net.IP) bool {
	if ip == nil {
		// or true?
		return false
	}

	addr := binary.BigEndian.Uint32(ip.To4())

	curr := &t.nodes[0]
	offset := uint32(0)
	for {
		matching := matchingPrefix(addr, curr.addr)
		offset += curr.prefix
		if matching < offset {
			return false
		}

		if curr.left == 0 || matching == 32 {
			return true
		}

		if (addr>>(32-(offset+1)))&0x1 == 0 {
			curr = &t.nodes[curr.left]
		} else {
			curr = &t.nodes[curr.right]
		}
	}
}
