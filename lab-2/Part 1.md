
#### Ping scans
discovery scan using -sn against your subnets
```
pi@raspberry:~$ sudo /sbin/iptables -Z
pi@raspberry:~$ nmap -sn 10.10.152.0/24 10.10.92.0/24 -oG discovery_scan.txt
Starting Nmap 7.80 ( https://nmap.org ) at 2024-02-08 00:52 UTC
Nmap scan report for 10.10.152.1
Host is up (0.0018s latency).
Nmap scan report for ics.ep.int.e-netsec.org (10.10.152.18)
Host is up (0.0010s latency).
Nmap scan report for updatesrv.ep.int.e-netsec.org (10.10.152.53)
Host is up (0.0012s latency).
Nmap scan report for 10.10.152.120
Host is up (0.0019s latency).
Nmap scan report for routerb.ep.int.e-netsec.org (10.10.152.129)
Host is up (0.00091s latency).
Nmap scan report for hr.ep.int.e-netsec.org (10.10.152.150)
Host is up (0.0024s latency).
Nmap done: 512 IP addresses (10 hosts up) scanned in 16.44 second
```

Traffic generated
```
pi@raspberry:~$ sudo /sbin/iptables -vn -L
Chain INPUT (policy ACCEPT 89 packets, 6536 bytes)
 pkts bytes target     prot opt in     out     source               destination
 1254  110K ACCEPT     all  --  *      *      !10.10.192.0/18       0.0.0.0/0

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination

Chain OUTPUT (policy ACCEPT 62 packets, 8064 bytes)
 pkts bytes target     prot opt in     out     source               destination
 6301  411K ACCEPT     all  --  *      *       0.0.0.0/0           !10.10.192.0/18
```

#### Full TCP Scan
```
pi@raspberry:~$ sudo /sbin/iptables -Z
pi@raspberry:~$ sudo nmap -sT 10.10.152.1 10.10.152.18 10.10.152.53 10.10.152.120 10.10.152.129 10.10.152.150
Starting Nmap 7.80 ( https://nmap.org ) at 2024-02-08 00:57 UTC
Nmap scan report for 10.10.152.1
Host is up (0.0011s latency).
Not shown: 996 filtered ports
PORT     STATE SERVICE
53/tcp   open  domain
80/tcp   open  http
443/tcp  open  https
2222/tcp open  EtherNetIP-1

Nmap scan report for ics.ep.int.e-netsec.org (10.10.152.18)
Host is up (0.0098s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
8083/tcp open  us-srv

Nmap scan report for updatesrv.ep.int.e-netsec.org (10.10.152.53)
Host is up (0.0095s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap scan report for 10.10.152.120
Host is up (0.0094s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
2022/tcp open  down

Nmap scan report for routerb.ep.int.e-netsec.org (10.10.152.129)
Host is up (0.0092s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
2022/tcp open  down

Nmap scan report for hr.ep.int.e-netsec.org (10.10.152.150)
Host is up (0.0086s latency).
Not shown: 992 closed ports
PORT     STATE SERVICE
80/tcp   open  http
111/tcp  open  rpcbind
139/tcp  open  netbios-ssn
443/tcp  open  https
445/tcp  open  microsoft-ds
901/tcp  open  samba-swat
2222/tcp open  EtherNetIP-1
3306/tcp open  mysql

Nmap done: 6 IP addresses (6 hosts up) scanned in 22.40 seconds
```

```
pi@raspberry:~$ sudo /sbin/iptables -vn -L
Chain INPUT (policy ACCEPT 195 packets, 13980 bytes)
 pkts bytes target     prot opt in     out     source               destination
 6278  312K ACCEPT     all  --  *      *      !10.10.192.0/18       0.0.0.0/0

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination

Chain OUTPUT (policy ACCEPT 117 packets, 14056 bytes)
 pkts bytes target     prot opt in     out     source               destination
13368  835K ACCEPT     all  --  *      *       0.0.0.0/0           !10.10.192.0/18
```


#### TCP syn scan
```
pi@raspberry:~$ sudo nmap -sS 10.10.152.1 10.10.152.18 10.10.152.53 10.10.152.120 10.10.152.129 10.10.152.150
Starting Nmap 7.80 ( https://nmap.org ) at 2024-02-08 01:17 UTC
Nmap scan report for 10.10.152.1
Host is up (0.00049s latency).
Not shown: 996 filtered ports
PORT     STATE SERVICE
53/tcp   open  domain
80/tcp   open  http
443/tcp  open  https
2222/tcp open  EtherNetIP-1

Nmap scan report for ics.ep.int.e-netsec.org (10.10.152.18)
Host is up (0.0013s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
8083/tcp open  us-srv

Nmap scan report for updatesrv.ep.int.e-netsec.org (10.10.152.53)
Host is up (0.0012s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap scan report for 10.10.152.120
Host is up (0.0012s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
2022/tcp open  down

Nmap scan report for routerb.ep.int.e-netsec.org (10.10.152.129)
Host is up (0.0011s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
2022/tcp open  down

Nmap scan report for hr.ep.int.e-netsec.org (10.10.152.150)
Host is up (0.0014s latency).
Not shown: 992 closed ports
PORT     STATE SERVICE
80/tcp   open  http
111/tcp  open  rpcbind
139/tcp  open  netbios-ssn
443/tcp  open  https
445/tcp  open  microsoft-ds
901/tcp  open  samba-swat
2222/tcp open  EtherNetIP-1
3306/tcp open  mysql

Nmap done: 6 IP addresses (6 hosts up) scanned in 13.70 seconds
```


```
pi@raspberry:~$ sudo /sbin/iptables -vn -L
Chain INPUT (policy ACCEPT 52 packets, 3564 bytes)
 pkts bytes target     prot opt in     out     source               destination
16337  716K ACCEPT     all  --  *      *      !10.10.192.0/18       0.0.0.0/0

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination

Chain OUTPUT (policy ACCEPT 42 packets, 6368 bytes)
 pkts bytes target     prot opt in     out     source               destination
27465 1456K ACCEPT     all  --  *      *       0.0.0.0/0           !10.10.192.0/18
```

