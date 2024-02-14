
## 3.1 Recorded MAC Addresses
Three IPs in the same address space :
##### 1. SERVER
1. IPv4 Address: 10.10.92.26
    - IPv6 Address: 2001:470:8cc5:3201:4e44:5bff:fe32:2aa
    - Hostname: server.ep.int.e-netsec.org
    - 4c:44:5b:32:02:aa [ether] on eth0
##### 2. CLIENT
1.  IPv4 Address: 10.10.92.20
    - IPv6 Address: 2001:470:8cc5:3201:4e44:5bff:fe32:3bb
    - Hostname: client.ep.int.e-netsec.org
    - 4c:44:5b:32:03:bb [ether] on eth0
##### 3. DNS
1. IPv4 Address: 10.10.92.2
    - Hostname: dns.ep.int.e-netsec.org
    -  IPv6 Address: 2001:470:8cc5:3202::1
##### 4. UPDSRV
IPv4 Address: 10.10.152.53
    - IPv6 Address: 2001:470:8cc5:3202::22
    - Hostname: updatesrv.ep.int.e-netsec.org

## 3.2 - A snippet of the ARP data right after the ARP poisoning

```bash
root@raspberry:/home/pi# tcpdump -n -i eth0 arp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
17:53:55.422729 ARP, Request who-has 10.10.92.2 tell 10.10.92.1, length 28
17:54:58.254863 ARP, Request who-has 10.10.92.20 tell 10.10.92.10, length 28
17:54:58.255268 ARP, Reply 10.10.92.20 is-at 4c:44:5b:32:03:bb, length 28
17:54:58.265641 ARP, Request who-has 10.10.92.26 tell 10.10.92.10, length 28
17:54:58.265866 ARP, Reply 10.10.92.26 is-at 4c:44:5b:32:02:aa, length 28
17:54:59.279134 ARP, Reply 10.10.92.26 is-at b8:27:eb:32:00:67, length 28
17:55:00.289413 ARP, Reply 10.10.92.26 is-at b8:27:eb:32:00:67, length 28
17:55:01.299855 ARP, Reply 10.10.92.26 is-at b8:27:eb:32:00:67, length 28
17:55:01.760754 ARP, Request who-has 10.10.92.26 tell 10.10.92.10, length 28
17:55:01.761052 ARP, Reply 10.10.92.26 is-at 4c:44:5b:32:02:aa, length 28
17:55:02.310089 ARP, Reply 10.10.92.26 is-at b8:27:eb:32:00:67, length 28
17:55:03.320298 ARP, Reply 10.10.92.26 is-at b8:27:eb:32:00:67, length 28
17:55:13.331819 ARP, Reply 10.10.92.26 is-at b8:27:eb:32:00:67, length 28
```


## 3.3 - FTP data between CLIENT and SERVER
```bash
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
17:09:02.304362 IP 10.10.92.20.59416 > 10.10.92.26.21: Flags [S], seq 1641554342, win 64240, options [mss 1460,sackOK,TS val 3715739894 ecr 0,nop,wscale 7], length 0
17:09:02.334755 IP 10.10.92.20.59416 > 10.10.92.26.21: Flags [S], seq 1641554342, win 64240, options [mss 1460,sackOK,TS val 3715739894 ecr 0,nop,wscale 7], length 0
17:09:03.313394 IP 10.10.92.20.59416 > 10.10.92.26.21: Flags [S], seq 1641554342, win 64240, options [mss 1460,sackOK,TS val 3715740903 ecr 0,nop,wscale 7], length 0
17:09:03.320513 IP 10.10.92.20.59416 > 10.10.92.26.21: Flags [S], seq 1641554342, win 64240, options [mss 1460,sackOK,TS val 3715740903 ecr 0,nop,wscale 7], length 0
17:09:05.332291 IP 10.10.92.20.59416 > 10.10.92.26.21: Flags [S], seq 1641554342, win 64240, options [mss 1460,sackOK,TS val 3715742918 ecr 0,nop,wscale 7], length 0
17:09:05.340610 IP 10.10.92.20.59416 > 10.10.92.26.21: Flags [S], seq 1641554342, win 64240, options [mss 1460,sackOK,TS val 3715742918 ecr 0,nop,wscale 7], length 0
17:10:01.980492 IP 10.10.92.20.59420 > 10.10.92.26.21: Flags [S], seq 398212420, win 64240, options [mss 1460,sackOK,TS val 3715799570 ecr 0,nop,wscale 7], length 0
17:10:01.990090 IP 10.10.92.20.59420 > 10.10.92.26.21: Flags [S], seq 398212420, win 64240, options [mss 1460,sackOK,TS val 3715799570 ecr 0,nop,wscale 7], length 0
17:10:02.988396 IP 10.10.92.20.59420 > 10.10.92.26.21: Flags [S], seq 398212420, win 64240, options [mss 1460,sackOK,TS val 3715800578 ecr 0,nop,wscale 7], length 0
17:10:02.992827 IP 10.10.92.20.59420 > 10.10.92.26.21: Flags [S], seq 398212420, win 64240, options [mss 1460,sackOK,TS val 3715800578 ecr 0,nop,wscale 7], length 0
17:10:05.004530 IP 10.10.92.20.59420 > 10.10.92.26.21: Flags [S], seq 398212420, win 64240, options [mss 1460,sackOK,TS val 3715802594 ecr 0,nop,wscale 7], length 0
```

## 3.4 - password line from ettercap showing the FTP username and password.
```bash
Mon Feb 12 19:09:01 2024 [762388]
TCP  10.10.92.20:59708 --> 10.10.92.26:21 | AP (13)
PASS S3cure.
FTP : 10.10.92.26:21 -> USER: ftpadmin  PASS: S3cure
```

## 3.5 - A snippet of the ARP data right after the ARP poisoner deactivated
```bash
01:38:21.289986 ARP, Reply 10.10.92.26 is-at b8:27:eb:32:00:67, length 28
01:38:27.088028 ARP, Reply 10.10.92.26 is-at 4c:44:5b:32:02:aa, length 28
01:38:28.098259 ARP, Reply 10.10.92.26 is-at 4c:44:5b:32:02:aa, length 28
01:38:29.108536 ARP, Reply 10.10.92.26 is-at 4c:44:5b:32:02:aa, length 28
```

## 3.6 - In the tcpdump output of FTP packets, why are only packets from CLIENT to SERVER shown?
`tcpdump -n -i eth0 port 21 and host CLIENT` shows only packets between client and the server because we use ettercap to redirect traffic from client to server through the jumphost.
Basically the jumphost acts as a MiTM and therefore the dump shows the conversation between client and server.

## 3.7 - A screenshot of the contents of the file on the FTP server
![[Pasted image 20240212203611.png]]

## 3.8 - The intercepted SSH credentials
``` bash

2488  write(5, "\0\0\0\fconfigpasswd", 16) = 16
2499  write(5, "\0\0\0\vconfigadmin", 15) = 15
```


## 3.9 - simple heuristic to detect ARP poisoning attacks?
1. Check for duplicate MAC addresses - The same MAC appearing in multiple places can imply address impersonation.
2. Detect excessive ARP traffic - Regular ARP broadcasts occur infrequently. High volumes of ARP packets could indicate poisoning.


## 3.10 - Link to a tool that you can install on your Linux machine to detect ARP poisoning.

[ArpWatch](https://www.kali.org/tools/arpwatch/)
## 3.11 - Differences between “atk6-parasite6” and “atk6-fake router26”

atk6-parasite6 sends spoofed neighbor solicitation replies to redirect traffic to our MAC adrress and poisons the neighbors cache rather than the routers.
Whereas atk6-fakerouter26 actively sends forged RA messages, and causes the victim to alter IPv6 routing by pointing default gateway to us. Therefore it can redirect both local and internet traffic acting as an actual router.

## 3.12 A screenshot of the intercepted authorized keys file and its original location (URL)
```bash
2001:470:8cc5:3202::22.80: Flags [P.], seq 0:162, ack 1, win 507, options [nop,nop,TS val 2499782539 ecr 4209662568], length 162: HTTP: GET /secret449/authorized_keys HTTP/1.1
```

```
root@raspberry:~# cat authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCpeaTX0yS2cunyw0k1d2w71eKOJ9rZsGfnDEiRD+4lVHqT6pJL9TCntaCR7pqB1mIA/Gusw5RVburFvArIfElEAjtLLl102Stu38cmOd1ybPZBxpjZIMpmKMMwIp2ssTZql+L/wgIl4MajD53gbti4NlQp6VAmhetl75rs7DXlhdWV4STXdNehnK1ir6i5GziwRzwgn9EINbGvdu9sFEijmRElmBujRJQrlVjYGETBwLMiMmvOxapv3jx3CBhtAAG/c2osAXN55mO3JVhaddtHR8kcbfcaNbztjhmwUhXLuGVSB246tRWBGIdqytO+kpETlY7I8wHgkp7JdufMV5Nh
```

## 3.13 - How can you protect yourself against IPv6 attacks?
1. Use strong encryption protocols for communication to protect data in transit.
2. Use Router Advertisement Guard where it makes sure that only authorised routers can send RA messages.
3. We can also use static IPv6 addresses wherever possible to stop automatic address assignments.
4. Deploy Intrusion Detection Systems.