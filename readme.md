# bithop beta v2

this spiders the bitcoin network for the purpose of retrieving every machine running `bitcoind` across ipv4/ipv6. these are appended to `nodes.txt` in the same directory as the script. let it run for awhile until you've databased the entire network, which should be > 18k nodes. it automatically removes duplicates from `nodes.txt` once every 1,000 `ip:port` discoveries. you may need to let the program max out/stall and run it a handful of times to database the entire network. unstable beta.

peers are discovered by exponentionally merging into them as spoofed nodes, following protocol specifications, and sending the `getaddr` protocol message which returns a node's peers in `ip:port` format. this technique is how bitnodes.io populates itself with node data - and to the best of my knowledge this is only other, and most performant, mainnet peer gatherer.

# how to use
```
snap install go --classic
git clone https://github.com/visualbasic6/bithop.git
cd bithop
go run bithop.go
```

# asciinema
[![heh](https://i.imgur.com/GbhffFl.png)](https://asciinema.org/a/666653)

# conclusion
bithop is another excercise in familiarizing myself with lower level code and golang. it could be reworked and expanded to be a sophisticated bitcoin block explorer - but i haven't the time nor desire.

follow https://x.com/123456 for updates - assuming there ever are any.
