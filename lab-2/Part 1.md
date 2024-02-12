### 1. Ping scans

```bash
Starting Nmap 7.80 ( https://nmap.org ) at 2024-02-10 23:23 UTC
Nmap scan report for 10.10.152.1
Host is up (0.0017s latency).
Nmap scan report for ics.ep.int.e-netsec.org (10.10.152.18)
Host is up (0.00095s latency).
Nmap scan report for updatesrv.ep.int.e-netsec.org (10.10.152.53)
Host is up (0.00058s latency).
Nmap scan report for 10.10.152.120
Host is up (0.00081s latency).
Nmap scan report for routerb.ep.int.e-netsec.org (10.10.152.129)
Host is up (0.00092s latency).
Nmap scan report for hr.ep.int.e-netsec.org (10.10.152.150)
Host is up (0.0018s latency).
Nmap scan report for dns.ep.int.e-netsec.org (10.10.92.2)
Host is up (0.0016s latency).
Nmap scan report for raspberry.ep.int.e-netsec.org (10.10.92.10)
Host is up (0.00017s latency).
Nmap scan report for client.ep.int.e-netsec.org (10.10.92.20)
Host is up (0.00064s latency).
Nmap scan report for server.ep.int.e-netsec.org (10.10.92.26)
Host is up (0.00063s latency).
Nmap done: 512 IP addresses (10 hosts up) scanned in 16.23 seconds
```

#### Network Traffic
```bash
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

### 2. Full TCP Scan
```bash
pi@raspberry:~$ sudo /sbin/iptables -Z
pi@raspberry:~$ sudo nmap -sT 10.10.152.1 10.10.152.18 10.10.152.53 10.10.152.120 10.10.152.129 10.10.152.150 10.10.92.2 10.10.92.10 10.10.92.20 10.10.92.26
Starting Nmap 7.80 ( https://nmap.org ) at 2024-02-10 17:52 UTC
Nmap scan report for 10.10.152.1
Host is up (0.00085s latency).
Not shown: 996 filtered ports
PORT     STATE SERVICE
53/tcp   open  domain
80/tcp   open  http
443/tcp  open  https
2222/tcp open  EtherNetIP-1

Nmap scan report for ics.ep.int.e-netsec.org (10.10.152.18)
Host is up (0.0067s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
8083/tcp open  us-srv

Nmap scan report for updatesrv.ep.int.e-netsec.org (10.10.152.53)
Host is up (0.0067s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap scan report for 10.10.152.120
Host is up (0.0068s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
2022/tcp open  down

Nmap scan report for routerb.ep.int.e-netsec.org (10.10.152.129)
Host is up (0.0068s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
2022/tcp open  down

Nmap scan report for hr.ep.int.e-netsec.org (10.10.152.150)
Host is up (0.0067s latency).
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

Nmap scan report for dns.ep.int.e-netsec.org (10.10.92.2)
Host is up (0.00086s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http
MAC Address: 0C:C4:7A:32:01:9A (Super Micro Computer)

Nmap scan report for client.ep.int.e-netsec.org (10.10.92.20)
Host is up (0.00095s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 4C:44:5B:32:03:BB (Unknown)

Nmap scan report for server.ep.int.e-netsec.org (10.10.92.26)
Host is up (0.0010s latency).
Not shown: 994 closed ports
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
443/tcp open  https
445/tcp open  microsoft-ds
MAC Address: 4C:44:5B:32:02:AA (Unknown)

Nmap scan report for raspberry.ep.int.e-netsec.org (10.10.92.10)
Host is up (0.00041s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
4444/tcp open  krb524

Nmap done: 10 IP addresses (10 hosts up) scanned in 21.89 seconds
```

#### Network Traffic
```bash
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


### 3. TCP syn scan
```bash
pi@raspberry:~$ sudo nmap -sS 10.10.152.1 10.10.152.18 10.10.152.53 10.10.152.120 10.10.152.129 10.10.152.150 10.10.92.2 10.10.92.10 10.10.92.20 10.10.92.26
Starting Nmap 7.80 ( https://nmap.org ) at 2024-02-10 17:54 UTC
Nmap scan report for 10.10.152.1
Host is up (0.00045s latency).
Not shown: 996 filtered ports
PORT     STATE SERVICE
53/tcp   open  domain
80/tcp   open  http
443/tcp  open  https
2222/tcp open  EtherNetIP-1

Nmap scan report for ics.ep.int.e-netsec.org (10.10.152.18)
Host is up (0.0011s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
8083/tcp open  us-srv

Nmap scan report for updatesrv.ep.int.e-netsec.org (10.10.152.53)
Host is up (0.0011s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap scan report for 10.10.152.120
Host is up (0.0011s latency).
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
Host is up (0.0013s latency).
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

Nmap scan report for dns.ep.int.e-netsec.org (10.10.92.2)
Host is up (0.000026s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http
MAC Address: 0C:C4:7A:32:01:9A (Super Micro Computer)

Nmap scan report for raspberry.ep.int.e-netsec.org (10.10.92.10)
Host is up (0.000018s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
4444/tcp open  krb524

Nmap scan report for client.ep.int.e-netsec.org (10.10.92.20)
Host is up (0.000026s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 4C:44:5B:32:03:BB (Unknown)

Nmap scan report for server.ep.int.e-netsec.org (10.10.92.26)
Host is up (0.000026s latency).
Not shown: 994 closed ports
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
443/tcp open  https
445/tcp open  microsoft-ds
MAC Address: 4C:44:5B:32:02:AA (Unknown)

Nmap done: 10 IP addresses (10 hosts up) scanned in 18.62 seconds
```

#### Network Traffic
``` bash
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

### 4.  The output of your UDP scan.
```bash

Nmap scan report for 10.10.152.1
Host is up (0.00076s latency).
Not shown: 1022 open|filtered ports
PORT    STATE SERVICE
53/udp  open  domain
123/udp open  ntp

Nmap scan report for ics.ep.int.e-netsec.org (10.10.152.18)
Host is up (0.00086s latency).
Not shown: 1022 closed ports
PORT    STATE         SERVICE
137/udp open          netbios-ns
138/udp open|filtered netbios-dgm

Nmap scan report for updatesrv.ep.int.e-netsec.org (10.10.152.53)
Host is up (0.00084s latency).
All 1024 scanned ports on updatesrv.ep.int.e-netsec.org (10.10.152.53) are closed

Nmap scan report for 10.10.152.120
Host is up (0.00079s latency).
Not shown: 1022 closed ports
PORT    STATE         SERVICE
67/udp  open|filtered dhcps
218/udp open|filtered mpp

Nmap scan report for routerb.ep.int.e-netsec.org (10.10.152.129)
Host is up (0.00083s latency).
Not shown: 1018 closed ports
PORT    STATE         SERVICE
67/udp  open|filtered dhcps
203/udp open|filtered at-3
250/udp open|filtered unknown
432/udp open|filtered iasd
688/udp open|filtered realm-rusd
922/udp open|filtered unknown

Nmap scan report for hr.ep.int.e-netsec.org (10.10.152.150)
Host is up (0.0036s latency).
Not shown: 1018 closed ports
PORT    STATE         SERVICE
68/udp  open|filtered dhcpc
111/udp open          rpcbind
137/udp open          netbios-ns
138/udp open|filtered netbios-dgm
605/udp open|filtered soap-beep
631/udp open|filtered ipp

Stats: 0:46:08 elapsed; 6 hosts completed (9 up), 3 undergoing UDP Scan
UDP Scan Timing: About 37.18% done; ETC: 02:23 (0:10:07 remaining)
Nmap scan report for dns.ep.int.e-netsec.org (10.10.92.2)
Host is up (0.00011s latency).
Not shown: 966 closed ports, 57 open|filtered ports
PORT   STATE SERVICE
53/udp open  domain
MAC Address: 0C:C4:7A:32:01:9A (Super Micro Computer)

Nmap scan report for client.ep.int.e-netsec.org (10.10.92.20)
Host is up (0.00011s latency).
All 1024 scanned ports on client.ep.int.e-netsec.org (10.10.92.20) are closed
MAC Address: 4C:44:5B:32:03:BB (Unknown)

Nmap scan report for server.ep.int.e-netsec.org (10.10.92.26)
Host is up (0.00010s latency).
Not shown: 1021 closed ports
PORT    STATE         SERVICE
137/udp open          netbios-ns
138/udp open|filtered netbios-dgm
631/udp open|filtered ipp
MAC Address: 4C:44:5B:32:02:AA (Unknown)

Nmap scan report for raspberry.ep.int.e-netsec.org (10.10.92.10)
Host is up (0.000042s latency).
All 1024 scanned ports on raspberry.ep.int.e-netsec.org (10.10.92.10) are closed

Nmap done: 10 IP addresses (10 hosts up) scanned in 3520.35 seconds
```

#### Traffic generated:
```bash
pi@raspberry:~$ sudo /sbin/iptables -vn -L
[sudo] password for pi:
Chain INPUT (policy ACCEPT 7563 packets, 544K bytes)
 pkts bytes target     prot opt in     out     source               destination
 696K   91M ACCEPT     all  --  *      *      !10.10.192.0/18       0.0.0.0/0

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination

Chain OUTPUT (policy ACCEPT 5946 packets, 2191K bytes)
 pkts bytes target     prot opt in     out     source               destination
2519K  157M ACCEPT     all  --  *      *       0.0.0.0/0           !10.10.192.0/18
```

### 5.  TCP SYN ping scan and “No Ping” scan.
The host that did not respond to ICMP ping requests was this:
```bash
Nmap scan report for corerouter.ep.int.e-netsec.org (10.10.92.1)
Host is up (0.00085s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE
53/tcp open  domain
```

### 6. OS scans
```bash
Starting Nmap 7.80 ( https://nmap.org ) at 2024-02-10 18:47 UTC

Nmap scan report for 10.10.152.1
Host is up (0.00051s latency).
Not shown: 996 filtered ports
PORT     STATE SERVICE
53/tcp   open  domain
80/tcp   open  http
443/tcp  open  https
2222/tcp open  EtherNetIP-1
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host

Nmap scan report for ics.ep.int.e-netsec.org (10.10.152.18)
Host is up (0.00059s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
8083/tcp open  us-srv
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=2/10%OT=22%CT=1%CU=38888%PV=Y%DS=2%DC=I%G=Y%TM=65C7C4C
OS:7%P=x86_64-pc-linux-gnu)SEQ(SP=FD%GCD=1%ISR=10F%TI=Z%TS=A)OPS(O1=M5B4ST1
OS:1NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW7%O6=M5B
OS:4ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T
OS:=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T
OS:2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=N
OS:)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
OS:IE(R=N)

Network Distance: 2 hops

Nmap scan report for updatesrv.ep.int.e-netsec.org (10.10.152.53)
Host is up (0.00064s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=2/10%OT=22%CT=1%CU=34839%PV=Y%DS=2%DC=I%G=Y%TM=65C7C4C
OS:7%P=x86_64-pc-linux-gnu)SEQ(SP=FC%GCD=1%ISR=105%TI=Z%II=I%TS=A)OPS(O1=M5
OS:B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW7%O
OS:6=M5B4ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%D
OS:F=Y%T=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0
OS:%Q=)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T
OS:6(R=N)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%R
OS:UD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops

Nmap scan report for 10.10.152.120
Host is up (0.00062s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
2022/tcp open  down
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=2/10%OT=22%CT=1%CU=35558%PV=Y%DS=2%DC=I%G=Y%TM=65C7C4C
OS:7%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=107%TI=Z%II=I%TS=A)OPS(O1=M
OS:5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW7%
OS:O6=M5B4ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%
OS:DF=Y%T=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=
OS:0%Q=)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
OS:T6(R=N)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%
OS:RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops

Nmap scan report for routerb.ep.int.e-netsec.org (10.10.152.129)
Host is up (0.00060s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
2022/tcp open  down
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=2/10%OT=22%CT=1%CU=43679%PV=Y%DS=2%DC=I%G=Y%TM=65C7C4C
OS:7%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=108%TI=Z%II=I%TS=A)OPS(O1=M
OS:5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW7%
OS:O6=M5B4ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%
OS:DF=Y%T=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=
OS:0%Q=)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
OS:T6(R=N)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%
OS:RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops

Nmap scan report for hr.ep.int.e-netsec.org (10.10.152.150)
Host is up (0.00089s latency).
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
Device type: general purpose
Running: Linux 3.X
OS CPE: cpe:/o:linux:linux_kernel:3
OS details: Linux 3.2 - 3.8
Network Distance: 3 hops

Nmap scan report for dns.ep.int.e-netsec.org (10.10.92.2)
Host is up (0.000077s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http
MAC Address: 0C:C4:7A:32:01:9A (Super Micro Computer)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=2/10%OT=22%CT=1%CU=32908%PV=Y%DS=1%DC=D%G=Y%M=0CC47A%T
OS:M=65C7C4D7%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10E%TI=Z%CI=Z%II=I
OS:%TS=A)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O
OS:5=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6
OS:=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O
OS:%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=
OS:0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%
OS:S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(
OS:R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=
OS:N%T=40%CD=S)

Network Distance: 1 hop

Nmap scan report for client.ep.int.e-netsec.org (10.10.92.20)
Host is up (0.000043s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 4C:44:5B:32:03:BB (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=2/10%OT=22%CT=1%CU=37844%PV=Y%DS=1%DC=D%G=Y%M=4C445B%T
OS:M=65C7C4D7%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=10D%TI=Z%CI=Z%II=I
OS:%TS=A)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O
OS:5=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6
OS:=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O
OS:%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=
OS:0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%
OS:S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(
OS:R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=
OS:N%T=40%CD=S)

Network Distance: 1 hop

Nmap scan report for server.ep.int.e-netsec.org (10.10.92.26)
Host is up (0.000051s latency).
Not shown: 994 closed ports
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
443/tcp open  https
445/tcp open  microsoft-ds
MAC Address: 4C:44:5B:32:02:AA (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=2/10%OT=21%CT=1%CU=30813%PV=Y%DS=1%DC=D%G=Y%M=4C445B%T
OS:M=65C7C4D7%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=104%TI=Z%CI=Z%II=I
OS:%TS=A)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O
OS:5=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6
OS:=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O
OS:%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=
OS:0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%
OS:S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(
OS:R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=
OS:N%T=40%CD=S)

Network Distance: 1 hop

Nmap scan report for raspberry.ep.int.e-netsec.org (10.10.92.10)
Host is up (0.000066s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
4444/tcp open  krb524
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6.32
OS details: Linux 2.6.32
Network Distance: 0 hops

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 10 IP addresses (10 hosts up) scanned in 52.71 seconds
```

#### Traffic generated
```bash
pi@raspberry:~$ sudo /sbin/iptables -vn -L
Chain INPUT (policy ACCEPT 238 packets, 17360 bytes)
 pkts bytes target     prot opt in     out     source               destination
 127K   32M ACCEPT     all  --  *      *      !10.10.192.0/18       0.0.0.0/0

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination

Chain OUTPUT (policy ACCEPT 170 packets, 35055 bytes)
 pkts bytes target     prot opt in     out     source               destination
 950K   43M ACCEPT     all  --  *      *       0.0.0.0/0           !10.10.192.0/18
```

### 7. Traffic comparison


### 8. Telnet and HTTP
```bash
pi@raspberry:~$ sudo telnet 10.10.152.1 80
Trying 10.10.152.1...
Connected to 10.10.152.1.
Escape character is '^]'.
GET / HTTP/1.0

HTTP/1.1 301 Moved Permanently
Server: nginx
Date: Thu, 08 Feb 2024 01:57:19 GMT
Content-Type: text/html
Content-Length: 162
Connection: close
Location: https:///
X-Frame-Options: SAMEORIGIN

<html>
<head><title>301 Moved Permanently</title></head>
<body>
<center><h1>301 Moved Permanently</h1></center>
<hr><center>nginx</center>
</body>
</html>
Connection closed by foreign host.



pi@raspberry:~$ sudo telnet 10.10.152.150 80
Trying 10.10.152.150...
Connected to 10.10.152.150.
Escape character is '^]'.
GET / HTTP/1.0

HTTP/1.1 200 OK
Date: Thu, 08 Feb 2024 01:57:14 GMT
Server: Apache/2.2.22 (Debian)
Last-Modified: Mon, 12 Sep 2022 21:06:01 GMT
ETag: "244c5-e6-5e881434f117c"
Accept-Ranges: bytes
Content-Length: 230
Vary: Accept-Encoding
Connection: close
Content-Type: text/html

<html><body><h1>Welcome to Corp-Sec HR!</h1>
<a href="/cgi-bin/uptime">Uptime</a><br>
<a href="/hr">HR Timesheet application</a>
<br>
Access the HR share ("hrshare") on Samba with user hrshare and password hrshare!
</body></html>
Connection closed by foreign host.



pi@raspberry:~$ sudo telnet 10.10.92.20 80
Trying 10.10.92.20...
Connected to 10.10.92.20.
Escape character is '^]'.
GET / HTTP/1.0

HTTP/1.1 200 OK
Date: Sat, 10 Feb 2024 18:57:25 GMT
Server: Apache/2.4.56 (Debian)
Vary: Accept-Encoding
Content-Length: 1435
Connection: close
Content-Type: text/html; charset=UTF-8

<h2>hostname -f</h2><pre>client.ep.int.e-netsec.org
</pre><h2>ip addr</h2><pre>1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0@if3629: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 4c:44:5b:32:03:bb brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.10.92.20/24 brd 10.10.92.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 2001:470:8cc5:3201:4e44:5bff:fe32:3bb/64 scope global dynamic mngtmpaddr
       valid_lft 86285sec preferred_lft 14285sec
    inet6 fe80::4e44:5bff:fe32:3bb/64 scope link
       valid_lft forever preferred_lft forever
</pre><h2>arp -a</h2><pre>raspberry.ep.int.e-netsec.org (10.10.92.10) at b8:27:eb:32:00:67 [ether] on eth0
server.ep.int.e-netsec.org (10.10.92.26) at 4c:44:5b:32:02:aa [ether] on eth0
server.ep.int.e-netsec.org (10.10.92.26) at 4c:44:5b:32:02:aa [ether] on eth0
</pre><h2>ip neighbor</h2><pre>10.10.92.10 dev eth0 lladdr b8:27:eb:32:00:67 REACHABLE
10.10.92.2 dev eth0 lladdr 0c:c4:7a:32:01:9a REACHABLE
10.10.92.26 dev eth0 lladdr 4c:44:5b:32:02:aa STALE
</pre><h2>last clientlist update</h2><pre>Sat Feb 10 18:57:02 UTC 2024
</pre>
Connection closed by foreign host.






pi@raspberry:~$ sudo telnet 10.10.92.26 80
Trying 10.10.92.26...
Connected to 10.10.92.26.
Escape character is '^]'.
GET / HTTP/1.0

HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Sat, 10 Feb 2024 18:56:37 GMT
Content-Type: text/html
Content-Length: 114
Last-Modified: Sun, 28 Jan 2024 16:59:32 GMT
Connection: close
ETag: "65b687f4-72"
Accept-Ranges: bytes

<html><body><a href=https://server.ep.int.e-netsec.org>Debug</a><br><a href=phpinfo.php>Phpinfo</a></body></html>
Connection closed by foreign host.
```
#### SSH
```bash
pi@raspberry:~$ sudo telnet 10.10.152.18 22
Trying 10.10.152.18...
Connected to 10.10.152.18.
Escape character is '^]'.
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4


pi@raspberry:~$ sudo telnet 10.10.152.53 22
Trying 10.10.152.53...
Connected to 10.10.152.53.
Escape character is '^]'.
SSH-2.0-OpenSSH_8.4p1 Debian-5


pi@raspberry:~$ sudo telnet 10.10.152.120 22
Trying 10.10.152.120...
Connected to 10.10.152.120.
Escape character is '^]'.
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4


pi@raspberry:~$ sudo telnet 10.10.152.129 22
Trying 10.10.152.129...
Connected to 10.10.152.129.
Escape character is '^]'.
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4


pi@raspberry:~$ sudo telnet 10.10.152.53 22
Trying 10.10.152.53...
Connected to 10.10.152.53.
Escape character is '^]'.
SSH-2.0-OpenSSH_8.4p1 Debian-5


pi@raspberry:~$ sudo telnet 10.10.92.20 22
Trying 10.10.92.20...
Connected to 10.10.92.20.
Escape character is '^]'.
SSH-2.0-OpenSSH_8.4p1 Debian-5

pi@raspberry:~$ sudo telnet 10.10.92.2 22
Trying 10.10.92.2...
Connected to 10.10.92.2.
Escape character is '^]'.
SSH-2.0-OpenSSH_8.4p1 Debian-5


pi@raspberry:~$ sudo telnet 10.10.92.26 22
Trying 10.10.92.26...
Connected to 10.10.92.26.
Escape character is '^]'.
SSH-2.0-OpenSSH_8.4p1 Debian-5



pi@raspberry:~$ sudo telnet 10.10.92.10 22
Trying 10.10.92.10...
Connected to 10.10.92.10.
Escape character is '^]'.
SSH-2.0-OpenSSH_8.4p1 Debian-5

```


### 9. Service Probes
```bash
pi@raspberry:~$ sudo nmap -sV -sS 10.10.152.1 10.10.152.18 10.10.152.53 10.10.152.120 10.10.152.129 10.10.152.150 10.10.92.2 10.10.92.10 10.10.92.20 10.10.92.26
[sudo] password for pi:
Starting Nmap 7.80 ( https://nmap.org ) at 2024-02-10 23:39 UTC
Nmap scan report for 10.10.152.1
Host is up (0.00050s latency).
Not shown: 996 filtered ports
PORT     STATE SERVICE  VERSION
53/tcp   open  domain   (generic dns response: NOTIMP)
80/tcp   open  http     nginx
443/tcp  open  ssl/http nginx
2222/tcp open  ssh      OpenSSH 7.9 (protocol 2.0)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :

Nmap scan report for ics.ep.int.e-netsec.org (10.10.152.18)
Host is up (0.0016s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
139/tcp  open  netbios-ssn Samba smbd 4.6.2
445/tcp  open  netbios-ssn Samba smbd 4.6.2
8083/tcp open  us-srv?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for updatesrv.ep.int.e-netsec.org (10.10.152.53)
Host is up (0.0016s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for 10.10.152.120
Host is up (0.0014s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
2022/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for routerb.ep.int.e-netsec.org (10.10.152.129)
Host is up (0.0013s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
2022/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for hr.ep.int.e-netsec.org (10.10.152.150)
Host is up (0.0014s latency).
Not shown: 992 closed ports
PORT     STATE SERVICE     VERSION
80/tcp   open  http        Apache httpd 2.2.22 ((Debian))
111/tcp  open  rpcbind     2-4 (RPC #100000)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: CORPSEC)
443/tcp  open  ssl/https?
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: CORPSEC)
901/tcp  open  http        Samba SWAT administration server
2222/tcp open  ssh         OpenSSH 6.0p1 Debian 4 (protocol 2.0)
3306/tcp open  mysql       MySQL (unauthorized)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Stats: 0:04:41 elapsed; 6 hosts completed (9 up), 3 undergoing Service Scan
Service scan Timing: About 81.82% done; ETC: 23:44 (0:00:27 remaining)
Stats: 0:04:46 elapsed; 6 hosts completed (9 up), 3 undergoing Service Scan
Service scan Timing: About 81.82% done; ETC: 23:44 (0:00:28 remaining)
Nmap scan report for dns.ep.int.e-netsec.org (10.10.92.2)
Host is up (0.000026s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
53/tcp open  domain  dnsmasq 2.85
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
MAC Address: 0C:C4:7A:32:01:9A (Super Micro Computer)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for client.ep.int.e-netsec.org (10.10.92.20)
Host is up (0.000025s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE  VERSION
22/tcp open  ssh      OpenSSH 8.4p1 Debian 5 (protocol 2.0)
80/tcp open  ssl/http Apache/2.4.56 (Debian)
MAC Address: 4C:44:5B:32:03:BB (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for server.ep.int.e-netsec.org (10.10.92.26)
Host is up (0.000026s latency).
Not shown: 994 closed ports
PORT    STATE SERVICE       VERSION
21/tcp  open  ftp           vsftpd 3.0.3
22/tcp  open  ssh           OpenSSH 8.4p1 Debian 5 (protocol 2.0)
80/tcp  open  http          nginx 1.18.0
139/tcp open  netbios-ssn?
443/tcp open  ssl/http      Apache httpd 2.4.56 ((Debian))
445/tcp open  microsoft-ds?
MAC Address: 4C:44:5B:32:02:AA (Unknown)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for raspberry.ep.int.e-netsec.org (10.10.92.10)
Host is up (0.000016s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
4444/tcp open  krb524?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 10 IP addresses (10 hosts up) scanned in 312.49 seconds
```

### 10. Method for ping
> What method does nmap use by default to ping a host?

By default, Nmap does host discovery and then performs a port scan against each host it determines is online. When we use the `-PE` option, Nmap sends ICMP echo requests (ping) to the target hosts to determine their online status. 
### 11. ICMP rate limit
> Describe how you could use the icmp ratelimit kernel parameter in Linux to slow down a  UDP scan

### 12. -sS or -sT? Why?
> Which nmap scan typically runs faster, -sS or -sT? Why?

-sS runs typically faster than -sT because -sS only sends out syn packets and never completes the TCP connection, whereas sT completes a connection.
Not only does -sT take longer and require more packets to obtain the same information, but target machines are more likely to log the connection.
### 13. Port Scanner
>In general, if any port scanner sends a datagram to a specific UDP port on a system and receives NO response, what can be concluded without any other information? (Hint: see the nmap man page, and consider networks which use firewalls.)

There are three scenarios:
	a. ICMP Port unreachable errors  - 3
	b. ICMP unreachable errors - 0, 1, 2, 9, 10, 13		
	c. No response or response with UDP Packet

In condition a, the port is closed, b marks the port as filtered whereas c, means that the port could be open or filters are blocking the communication.
Therefore, no response means that the port could be open.
### 14. (Bonus) 
>Describe your results using ZMap scanning the virtual network. Discuss the differ- ences between nmap and ZMap, in terms of design, functionality, techniques, and performance.
### 15. DNS enumeration
> What additional DNS names did you find with DNS enumeration?

nice.ep.int.e-netsec.org and crew.ep.int.e-netsec.org
```bash
pi@raspberry:~$ sudo dnsmap ep.int.e-netsec.org -w /root/wordlists/dns4.wordlist
dnsmap 0.35 - DNS Network Mapper

[+] searching (sub)domains for ep.int.e-netsec.org using /root/wordlists/dns4.wordlist
[+] using maximum random delay of 10 millisecond(s) between requests

nice.ep.int.e-netsec.org
IP address #1: 10.10.3.134
[+] warning: internal IP address disclosed

crew.ep.int.e-netsec.org
IP address #1: 10.10.3.87
[+] warning: internal IP address disclosed

[+] 2 (sub)domains and 2 IP address(es) found
[+] 2 internal IP address(es) disclosed
[+] completion time: 1 second(s)
```


### 16. CA Logs:
>Which secret host did you find using the Certificate Transparency log? 

alpha-development.ep.int.e-netsec.org

> Which CA generated how many certificates for your team’s network?
    
    commonName                = R3  
    organizationName          = Let's Encrypt  
    countryName               = US
    Generated 8 Certificates to our team's network

1. 8 Certificates issued to our team's network.
2. Which secret server in the 10.10.4.0/24 network has a certificate with your team’s DNS suffix?
	``` bash
	pi@raspberry:~$ dig alpha-development.ep.int.e-netsec.org
	; <<>> DiG 9.16.27-Debian <<>> alpha-development.ep.int.e-netsec.org
	;; global options: +cmd
	;; Got answer:
	;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 20374
	;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
	
	;; OPT PSEUDOSECTION:
	; EDNS: version: 0, flags:; udp: 1232
	;; QUESTION SECTION:
	;alpha-development.ep.int.e-netsec.org. IN A
	
	;; ANSWER SECTION:
	alpha-development.ep.int.e-netsec.org. 0 IN A   10.10.4.176
	
	;; Query time: 4 msec
	;; SERVER: 10.10.92.1#53(10.10.92.1)
	;; WHEN: Sat Feb 10 20:39:16 UTC 2024
	;; MSG SIZE  rcvd: 82
```
	Therefore the server is `alpha-development.ep.int.e-netsec.org` associated with `10.10.4.176`

3. CA Used by 'e-netsec.org':
	    `commonName                = GTS Root R1  
	    `organizationName          = Google Trust Services LLC`  
	    `countryName              = US`

### 17.  Tabular view
Using the information gathered through the port scanning task and the fingerprinting task, describe in detail various nodes of the network 7 Make sure to include the following details: i) Node IP addresses and hostname, ii) operating system information including patch number (e.g Ubuntu 16.04.6 LTS), iii) running services and open ports and iv) services and service version numbers. Make sure to include both, IPv4 and IPv6 addresses.
	Important Note. Please include all the hostnames and IPs found in the DNS enumeration and Certificate part in the table (you cannot actually access these machines)!


**Node 1:**
- IPv4 Address:  10.10.152.1

| Port (Protocol) | Service | Version |
| ---- | ---- | ---- |
| 53/tcp | domain | (generic dns response: NOTIMP) |
| 80/tcp | http | nginx |
| 443/tcp | https | nginx |
| 2222/tcp | EtherNetIP-1 | OpenSSH 7.9 (protocol 2.0) |
**Node 2:**
    - IPv4 Address: 10.10.152.18
    - IPv6 Address: 2001:470:8cc5:3202:20c:87ff:fe32:652
    - Hostname: ics.ep.int.e-netsec.org
    - Operating System: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4

|Port (Protocol)|Service|Version|
|---|---|---|
|22/tcp|ssh|OpenSSH 8.2p1 Ubuntu 4 (protocol 2.0) |
|139/tcp|netbios-ssn|Samba smbd 4.6.2|
|445/tcp|microsoft-ds |Samba smbd 4.6.2|
|8083/tcp|us-srv |-|
**Node 3:**
    - IPv4 Address: 10.10.152.53
    - IPv6 Address: 2001:470:8cc5:3202::22
    - Hostname: updatesrv.ep.int.e-netsec.org
    - Operating System: SSH-2.0-OpenSSH_8.4p1 Debian-5
    
| Port (Protocol) | Service | Version |
| ---- | ---- | ---- |
| 22/tcp | ssh | OpenSSH 8.4p1 Debian 5 (protocol 2.0) |
| 80/tcp | http | Apache httpd 2.4.56 (Debian) |
**Node 4:**
    - IPv4 Address: 10.10.152.120

|Port (Protocol)|Service|Version|
|---|---|---|
|22/tcp|ssh|OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)|
|2022/tcp|down |OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)|

**Node 5:**
    - IPv4 Address: 10.10.152.129
    - IPv6 Address: 2001:470:8cc5:3203::1
    - Hostname: routerb.ep.int.e-netsec.org
    - Operating System: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4
    
|Port (Protocol)|Service|Version|
|---|---|---|
|22/tcp|ssh|OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)|
|2022/tcp|down |OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)|
**Node 6:**
    - IPv4 Address: 10.10.152.150
    - IPv6 Address: 2001:470:8cc5:3203:eece:13ff:feea:32f3
    - Hostname: hr.ep.int.e-netsec.org
    - Operating System: Linux 3.2 - 3.8

|Port (Protocol)|Service|Version|
|---|---|---|
|80/tcp|http|Apache httpd 2.2.22 (Debian)|
|111/tcp|rpcbind|2-4 (RPC #100000)|
|139/tcp|netbios-ssn|Samba smbd 3.X - 4.X|
|443/tcp|https |-|
|445/tcp|microsoft-ds |Samba smbd 3.X - 4.X|
|901/tcp|samba-swat |Samba SWAT administration server|
|2222/tcp|EtherNetIP-1 |OpenSSH 6.0p1 Debian 4 (protocol 2.0)|
|3306/tcp|mysql|MySQL |
**Node 7:**
    - IPv4 Address: 10.10.92.1
    - IPv6 Address: 2001:470:8cc5:3202::1
    - Hostname: corerouter.ep.int.e-netsec.org

| Port (Protocol) | Service | Version |
| ---- | ---- | ---- |
| 53/tcp | domain | dnsmasq 2.85 |
 **Node 8:**
    - IPv4 Address: 10.10.92.2
    - Hostname: dns.ep.int.e-netsec.org
    -  IPv6 Address: 2001:470:8cc5:3202::1
    - Operating System: SSH-2.0-OpenSSH_8.4p1 Debian-5

| Port (Protocol) | Service | Version |
| ---- | ---- | ---- |
| 22/tcp | ssh | OpenSSH 8.4p1 Debian 5 (protocol 2.0) |
| 53/tcp | domain | dnsmasq 2.85 |
| 80/tcp | http | Apache httpd 2.4.56 (Debian) |

**Node 9:**
    - IPv4 Address: 10.10.92.10
    - Hostname: raspberry.ep.int.e-netsec.org
    - Operating System: SSH-2.0-OpenSSH_8.4p1 Debian-5

|Port (Protocol)|Service|Version|
|---|---|---|
|22/tcp|ssh|OpenSSH 8.4p1 Debian 5 (protocol 2.0)|
|4444/tcp|krb524 |-|
**Node 10:**
    - IPv4 Address: 10.10.92.20
    - IPv6 Address: 2001:470:8cc5:3201:4e44:5bff:fe32:3bb
    - Hostname: client.ep.int.e-netsec.org
    - Operating System: SSH-2.0-OpenSSH_8.4p1 Debian-5

|Port (Protocol)|Service|Version|
|---|---|---|
|22/tcp|ssh|OpenSSH 8.4p1 Debian 5 (protocol 2.0)|
|80/tcp|http |Apache/2.4.56 (Debian)|
**Node 11:**
    - IPv4 Address: 10.10.92.26
    - IPv6 Address: 2001:470:8cc5:3201:4e44:5bff:fe32:2aa
    - Hostname: server.ep.int.e-netsec.org
    - Operating System: SSH-2.0-OpenSSH_8.4p1 Debian-5

|Port (Protocol)|Service|Version|
|---|---|---|
|21/tcp|ftp|vsftpd 3.0.3|
|22/tcp|ssh|OpenSSH 8.4p1 Debian 5 (protocol 2.0)|
|80/tcp|http|nginx 1.18.0|
|139/tcp|netbios-ssn |-|
|443/tcp|https |Apache httpd 2.4.56 ((Debian))|
|445/tcp|microsoft-ds |-|
