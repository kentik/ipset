package ipset

import "net"

type ipv6Node struct {
}

type treeV6 struct {
	// nodes []ipv6Node
	nets []*net.IPNet
}

func (t *treeV6) Add(cidr *net.IPNet) {
	t.nets = append(t.nets, cidr)
	return
}

func (t *treeV6) Contains(ip net.IP) bool {
	for _, net := range t.nets {
		if net.Contains(ip) {
			return true
		}
	}
	return false
}
