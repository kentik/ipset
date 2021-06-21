# ipset

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
