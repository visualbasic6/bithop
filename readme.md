# bithop beta

this spiders the bitcoin network for the purpose of retrieving ipv4/ipv6_ip:port. these are appended to nodes.txt in the same directory as the script. this beta is unstable. if you encounter "sigint: killed" - you may want to `mv nodes.txt nodes1.txt` and restart the script. i'll fix that when i feel like it - as for now i've just dupekilled a handful of runs and have returned the entire network.

# instructions
```
snap install go --classic
git clone https://github.com/visualbasic6/bithop.git
cd bithop
go run bithop.go
```
