# bithop beta

this spiders the bitcoin network for the purpose of retrieving ipv4/ipv6_ip:port. these are appended to nodes.txt in the same directory as the script. this beta is unstable. if you encounter "signal: killed" - you may want to `mv nodes.txt nodes1.txt`, restart the script and use a lower thread count. if you encounter this issue - repeat the script a handful of times and dupekill output until you've databased the complete network.

# instructions
```
snap install go --classic
git clone https://github.com/visualbasic6/bithop.git
cd bithop
go run bithop.go
```
