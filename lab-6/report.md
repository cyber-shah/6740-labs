# 6.4

"Try to connect from RaspberryPi to both the IPv4 and IPv6 address ROUTERB on
port 22. What do you observe?"

`ssh root@10.10.152.129 -p 22` hangs forever. I think it would probably have timed out if I left it running for long enough, but I left it running for 2 minutes and it just kept hanging.

sshing on ipv6 still works: `ssh root@2001:470:8cc5:3202::120 -p 22`, because we only filtered ipv4 traffic with the above rules. If we wanted to also block ipv6 ssh, we should use ip6tables to add rules.

To allow our vpn address (at ip 10.10.222.2) to access routerb, we add the following rule:

```
iptables -I INPUT -s 10.10.222.2 -p all -i eth0 -j ACCEPT
```


# 6.5

the HR machine has ipv4 `10.10.152.150` and ipv6 `2001:470:8cc5:3203:eece:13ff:feea:32f3`.

Trying to connect to the ipv4 ip from the raspberry pi hangs forever:

```
root@raspberry:~# wget 10.10.152.150
--2024-03-31 07:54:38--  http://10.10.152.150/
Connecting to 10.10.152.150:80...
```

while accessing the ipv6 ip works, because we only added a filtering rule for ipv4:

```
root@raspberry:~# wget http://[2001:470:8cc5:3203:eece:13ff:feea:32f3]
--2024-03-31 07:56:41--  http://[2001:470:8cc5:3203:eece:13ff:feea:32f3]/
Connecting to [2001:470:8cc5:3203:eece:13ff:feea:32f3]:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 230 [text/html]
Saving to: 'index.html'

index.html                           100%[====================================================================>]     230  --.-KB/s    in 0s

2024-03-31 07:56:41 (13.4 MB/s) - 'index.html' saved [230/230]

root@raspberry:~# cat index.html
<html><body><h1>Welcome to Corp-Sec HR!</h1>
<a href="/cgi-bin/uptime">Uptime</a><br>
<a href="/hr">HR Timesheet application</a>
<br>
Access the HR share ("hrshare") on Samba with user hrshare and password hrshare!
</body></html>
root@raspberry:~#
```


We use the following commands,in order, to accomplish the requested filtering:

```
# Allow all access from 10.10.192.0/18 to HR (IPv4 only)
iptables -A FORWARD -s 10.10.192.0/18 -d 10.10.152.150 -j ACCEPT
# Allow traffic from RaspberryPi to TCP port 80 and 443
iptables -A FORWARD -p tcp -s 10.10.92.10 --dport 80 -j ACCEPT
iptables -A FORWARD -p tcp -s 10.10.92.10 --dport 443 -j ACCEPT
# Block all network traffic from 10.10.1.5 to HR (IPv4 only)
iptables -A FORWARD -s 10.10.1.5 -d 10.10.152.150 -j DROP
# Drop all IPv6 traffic from the HR network
ip6tables -A FORWARD -i eth1 -j DROP
```

The rules are in the files `6.5 ipv4.rules` and `6.5 ipv6.rules`.

# 6.6


We'll add the following iptables rules

```
# allow traffic to pass routerb and not get caught by our earlier rules
iptables -I FORWARD 1 -p tcp --dport 443 -j ACCEPT
iptables -I INPUT 1 -p tcp --dport 80 -j ACCEPT
# prerouting rules fo redirections
iptables -t nat -A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination 10.10.152.15:80
iptables -t nat -A PREROUTING -p tcp --dport 8443 -j DNAT --to-destination 10.10.152.15:443
```

"Test and document the following cases:"

Most of these cases work and display a webpage:
- http://10.10.152.129:8080/ does not work, because although we whitelisted traffic from 10.10.192.0/18, we only did so when the traffic was to HR, not to routerb.
- https://hr.ep.int.e-netsec.org:443/ works because we whitelisted traffic from 10.10.192.0/18 to HR
- https://hr.ep.int.e-netsec.org:8443/ works because we whitelisted traffic from 10.10.192.0/18 to HR, and redirected traffic from HR port 8443 to HR port 443
- `wget http://10.10.152.129:8080/` does not work because we only whitelisted raspberry pi traffic to routerb on tcp port 80 and 443
- `wget http://[2001:470:8cc5:3203:eece:13ff:feea:32f3]:8080/` works because we never set a filter rule for ipv6
- `wget https://hr.ep.int.e-netsec.org/` works because we whitelisted rpi traffic on port 443
- `wget https://hr.ep.int.e-netsec.org:8443/` works because we whitelisted rpi traffic on port 443, and redirected HR port 8443 to HR port 443

# 6.8

"Submit the rules for the INPUT, FORWARD and NAT chain (both iptables and ip6tables)"

The final rules are in `6.8 ipv4.rules`, `6.8 ipv4 nat.rules`, `6.8 ipv6.rules`, and `6.8 ipv6 nat.rules`.

"What were your observations when you tried to connect to SSH after applying the INPUT
rules (IPv4, IPv6)? Explain why."

Copying what I wrote for 6.4:

> `ssh root@10.10.152.129 -p 22` hangs forever. I think it would probably have timed out if I left it running for long enough, but I left it running for 2 minutes and it just kept hanging.

> sshing on ipv6 still works: `ssh root@2001:470:8cc5:3202::120 -p 22`, because we only filtered ipv4 traffic with the above rules. If we wanted to also block ipv6 ssh, we should use ip6tables to add rules.

"Why does the File Transfer Protocol (FTP) pose a problem for firewalls? If you had blocked
all traffic on your firewall, what iptables commands would you use to allow outgoing FTP
connections from ROUTERB?"

FTP poses a problem for firewalls because it negotiates a random port for incoming connections, which can be difficult to track and properly filter for.

FTP uses port 20 for outgoing connections, so the following rule would allow it: `iptables -A OUTPUT -p tcp --sport 20 -j ACCEPT`.

"From your observations of using iptables and ip6tables, what security risks might exist if
developers or admins are not aware of the difference between IPv4 and IPv6?"

If an admin is not aware that `iptables` rules only apply to ipv4 and not to ipv6, they might only set a rule for ipv6 but think it applies to all connections (both ipv4 and ipv6). This means that someone could use the ipv6 address of a website to get around the firewall which is only in place for ipv4.
