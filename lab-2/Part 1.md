# Part 1

## 1. Ping scans
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

## 2. Full TCP Scan
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


## 3. TCP syn scan
```bash
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

## 4.  

## 5.  


# Part 2
## 6. OS scans
```

pi@raspberry:~$ sudo nmap -O 10.10.152.1 10.10.152.18 10.10.152.53 10.10.152.120 10.10.152.129 10.10.152.150
Starting Nmap 7.80 ( https://nmap.org ) at 2024-02-08 01:51 UTC
Nmap scan report for 10.10.152.1
Host is up (0.00052s latency).
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
Host is up (0.00077s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
8083/tcp open  us-srv
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=2/8%OT=22%CT=1%CU=33001%PV=Y%DS=2%DC=I%G=Y%TM=65C433C1
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10C%TI=Z%TS=A)OPS(O1=M5B4ST1
OS:1NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW7%O6=M5B
OS:4ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T
OS:=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T
OS:2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=N
OS:)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
OS:IE(R=N)

Network Distance: 2 hops

Nmap scan report for updatesrv.ep.int.e-netsec.org (10.10.152.53)
Host is up (0.00076s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=2/8%OT=22%CT=1%CU=43747%PV=Y%DS=2%DC=I%G=Y%TM=65C433C1
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10C%TI=Z%II=I%TS=A)OPS(O1=M5
OS:B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW7%O
OS:6=M5B4ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%D
OS:F=Y%T=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0
OS:%Q=)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T
OS:6(R=N)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%R
OS:UD=G)U1(R=N)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops

Nmap scan report for 10.10.152.120
Host is up (0.00073s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
2022/tcp open  down
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=2/8%OT=22%CT=1%CU=34682%PV=Y%DS=2%DC=I%G=Y%TM=65C433C1
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10A%TI=Z%II=I%TS=A)OPS(O1=M5
OS:B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW7%O
OS:6=M5B4ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%D
OS:F=Y%T=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0
OS:%Q=)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T
OS:6(R=N)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%R
OS:UD=G)U1(R=N)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops

Nmap scan report for routerb.ep.int.e-netsec.org (10.10.152.129)
Host is up (0.00073s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
2022/tcp open  down
Aggressive OS guesses: Linux 2.6.32 (94%), Linux 2.6.32 or 3.10 (93%), Linux 4.4 (93%), Linux 2.6.32 - 2.6.35 (92%), Linux 2.6.32 - 2.6.39 (92%), Linux 4.0 (91%), Linux 3.11 - 4.1 (89%), Linux 3.2 - 3.8 (89%), Linux 2.6.18 (89%), Linux 2.6.32 - 3.0 (89%)
No exact OS matches for host (test conditions non-ideal).

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
Device type: general purpose
Running: Linux 3.X
OS CPE: cpe:/o:linux:linux_kernel:3
OS details: Linux 3.2 - 3.8
Network Distance: 3 hops

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 6 IP addresses (6 hosts up) scanned in 35.44 seconds
```


## 7. Traffic comparison
## 8. Telnet and HTTP
```
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
```

### SSH
```
pi@raspberry:~$ sudo telnet 10.10.152.18 22
Trying 10.10.152.18...
Connected to 10.10.152.18.
Escape character is '^]'.
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4
^Cq
Connection closed by foreign host.

pi@raspberry:~$ sudo telnet 10.10.152.120 22
Trying 10.10.152.120...
Connected to 10.10.152.120.
Escape character is '^]'.
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4
^C
Connection closed by foreign host.

pi@raspberry:~$ sudo telnet 10.10.152.129 22
Trying 10.10.152.129...
Connected to 10.10.152.129.
Escape character is '^]'.
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4
^C
Connection closed by foreign host.

pi@raspberry:~$ sudo telnet 10.10.152.53 22
Trying 10.10.152.53...
Connected to 10.10.152.53.
Escape character is '^]'.
SSH-2.0-OpenSSH_8.4p1 Debian-5
^C
Connection closed by foreign host.
```


## 9. Service Probes
```
pi@raspberry:~$ sudo nmap -sV -sS 10.10.152.1 10.10.152.18 10.10.152.53 10.10.152.120 10.10.152.129 10.10.152.150
Starting Nmap 7.80 ( https://nmap.org ) at 2024-02-08 02:02 UTC
Stats: 0:01:38 elapsed; 0 hosts completed (6 up), 6 undergoing Service Scan
Service scan Timing: About 90.91% done; ETC: 02:04 (0:00:08 remaining)
Stats: 0:01:58 elapsed; 0 hosts completed (6 up), 6 undergoing Service Scan
Service scan Timing: About 90.91% done; ETC: 02:04 (0:00:10 remaining)
Stats: 0:02:03 elapsed; 0 hosts completed (6 up), 6 undergoing Service Scan
Service scan Timing: About 90.91% done; ETC: 02:05 (0:00:11 remaining)
Nmap scan report for 10.10.152.1
Host is up (0.00071s latency).
Not shown: 996 filtered ports
PORT     STATE SERVICE  VERSION
53/tcp   open  domain   (generic dns response: NOTIMP)
80/tcp   open  http     nginx
443/tcp  open  ssl/http nginx
2222/tcp open  ssh      OpenSSH 7.9 (protocol 2.0)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=2/8%Time=65C43664%P=x86_64-pc-linux-gnu%r(DNSVe
SF:rsionBindReqTCP,20,"\0\x1e\0\x06\x81\x85\0\x01\0\0\0\0\0\0\x07version\x
SF:04bind\0\0\x10\0\x03")%r(DNSStatusRequestTCP,E,"\0\x0c\0\0\x90\x04\0\0\
SF:0\0\0\0\0\0");

Nmap scan report for ics.ep.int.e-netsec.org (10.10.152.18)
Host is up (0.0013s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
139/tcp  open  netbios-ssn   Samba smbd 4.6.2
445/tcp  open  microsoft-ds?
8083/tcp open  us-srv?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8083-TCP:V=7.80%I=7%D=2/8%Time=65C43665%P=x86_64-pc-linux-gnu%r(Fou
SF:rOhFourRequest,62,"HTTP/1\.1\x20302\x20Found\r\nContent-Length:\x200\r\
SF:nX-FHEM-csrfToken:\x20csrf_168872777155443\r\nLocation:\x20/fhem\r\n\r\
SF:n")%r(GenericLines,5E,"HTTP/1\.1\x20405\x20Method\x20Not\x20Allowed\r\n
SF:X-FHEM-csrfToken:\x20csrf_168872777155443\r\nContent-Length:\x200\r\n\r
SF:\n")%r(HTTPOptions,4E,"HTTP/1\.1\x20200\x20OK\r\nX-FHEM-csrfToken:\x20c
SF:srf_168872777155443\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest,4E,
SF:"HTTP/1\.1\x20200\x20OK\r\nX-FHEM-csrfToken:\x20csrf_168872777155443\r\
SF:nContent-Length:\x200\r\n\r\n")%r(SIPOptions,4E,"HTTP/1\.1\x20200\x20OK
SF:\r\nX-FHEM-csrfToken:\x20csrf_168872777155443\r\nContent-Length:\x200\r
SF:\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for updatesrv.ep.int.e-netsec.org (10.10.152.53)
Host is up (0.0013s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for 10.10.152.120
Host is up (0.0013s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
2022/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for routerb.ep.int.e-netsec.org (10.10.152.129)
Host is up (0.0012s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
2022/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap scan report for hr.ep.int.e-netsec.org (10.10.152.150)
Host is up (0.0015s latency).
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

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 6 IP addresses (6 hosts up) scanned in 160.56 seconds
```
