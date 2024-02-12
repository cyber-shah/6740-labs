
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
17:10:05.008665 IP 10.10.92.20.59420 > 10.10.92.26.21: Flags [S], seq 398212420, win 64240, options [mss 1460,sackOK,TS val 3715802594 ecr 0,nop,wscale 7], length 0
17:11:01.346279 IP 10.10.92.20.59422 > 10.10.92.26.21: Flags [S], seq 1505714558, win 64240, options [mss 1460,sackOK,TS val 3715858936 ecr 0,nop,wscale 7], length 0
17:11:01.352649 IP 10.10.92.20.59422 > 10.10.92.26.21: Flags [S], seq 1505714558, win 64240, options [mss 1460,sackOK,TS val 3715858936 ecr 0,nop,wscale 7], length 0
17:11:02.348594 IP 10.10.92.20.59422 > 10.10.92.26.21: Flags [S], seq 1505714558, win 64240, options [mss 1460,sackOK,TS val 3715859938 ecr 0,nop,wscale 7], length 0
17:11:02.364915 IP 10.10.92.20.59422 > 10.10.92.26.21: Flags [S], seq 1505714558, win 64240, options [mss 1460,sackOK,TS val 3715859938 ecr 0,nop,wscale 7], length 0
17:11:04.364461 IP 10.10.92.20.59422 > 10.10.92.26.21: Flags [S], seq 1505714558, win 64240, options [mss 1460,sackOK,TS val 3715861954 ecr 0,nop,wscale 7], length 0
17:11:04.376582 IP 10.10.92.20.59422 > 10.10.92.26.21: Flags [S], seq 1505714558, win 64240, options [mss 1460,sackOK,TS val 3715861954 ecr 0,nop,wscale 7], length 0
```


```bash

17:46:20.358726 ARP, Ethernet (len 6), IPv4 (len 4), Reply 10.10.92.26 is-at 4c:44:5b:32:02:aa, length 28
17:46:21.368949 ARP, Ethernet (len 6), IPv4 (len 4), Reply 10.10.92.26 is-at 4c:44:5b:32:02:aa, length 28
17:46:22.406184 ARP, Ethernet (len 6), IPv4 (len 4), Reply 10.10.92.26 is-at 4c:44:5b:32:02:aa, length 28

```



```bash
Mon Feb 12 19:09:01 2024 [762388]
TCP  10.10.92.20:59708 --> 10.10.92.26:21 | AP (13)
PASS S3cure.
FTP : 10.10.92.26:21 -> USER: ftpadmin  PASS: S3cure
```
