package ipset

import "net"

type ipv6Node struct {
}

type treeV6 struct {
	nodes []ipv6Node
}

func (t *treeV6) Add(cidr *net.IPNet) {
	return
}

func (t *treeV6) Contains(ip net.IP) bool {
	return false
}
