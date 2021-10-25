# ipset

![CI](https://github.com/kentik/ipset/workflows/CI/badge.svg)
[![GitHub Release](https://img.shields.io/github/release/kentik/ipset.svg?style=flat)](https://github.com/kentik/ipset/releases/latest)
[![Coverage Status](https://coveralls.io/repos/github/kentik/ipset/badge.svg?branch=main)](https://coveralls.io/github/kentik/ipset?branch=main)
[![Go Report Card](https://goreportcard.com/badge/github.com/kentik/ipset)](https://goreportcard.com/report/github.com/kentik/ipset) 


ipset is a Go library for dealing with sets of CIDR prefixes.  It uses a radix tree
(r=2), also called a Patricia trie. 

After creating an `ipset.Set` and populating it with prefixes, the `Contains` function
can be used to check if a given address is contained by any of the prefixes in the set.

## Usage

```
import "github.com/kentik/ipset"

set := ipset.NewSetFromCSV("10.0.0.0/8,172.16.0.0/16,192.168.0.0/255")
contained := set.Contains(net.ParseIP("10.1.128.0"))
```

## License

See [LICENSE](LICENSE) for license information.
