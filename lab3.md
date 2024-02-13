
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

## 3.7 - A screenshot of the contents of the file on the FTP server
![[Pasted image 20240212203611.png]]




Tue Feb 13 04:08:01 2024 [231320]
TCP  10.10.92.26:23080 --> 10.10.92.20:43644 | AP (1254)
.com,Maught,isheiQu1ai,202-969-7975,Visa,4485180956474700,417,11/2027,10/26/2000
Benjamin,K,Dreher,"340 Concord Street",Matthews,NC,28105,US,BenjaminDreher@rhyta.com,Whort2002,aeG9vaifa7I,704-589-1592,Visa,4916936094526035,482,3/2025,6/6/2002
Margaret,J,Conley,"3239 Hickman Street","Burr Ridge",IL,60527,US,MargaretJConley@teleworm.us,Piceplonse,aiphemooY3,630-419-2407,MasterCard,5342101143218800,692,10/2027,11/9/1999
Antonio,M,Hazzard,"3446 Zimmerman Lane","Los Angeles",CA,90071,US,AntonioMHazzard@armyspy.com,Tirs1996,Veeyoe7g,213-489-8134,MasterCard,5138395529348276,068,11/2026,8/1/1996
Sienna,T,Graham,"1485 Modoc Alley",Meridian,ID,83642,US,SiennaGraham@teleworm.us,Likedest95,aW2mie0e,208-846-1414,MasterCard,5393529302171725,398,3/2023,10/2/1995
Corette,M,Dionne,"466 Frum Street",Nashville,TN,37212,US,CoretteDionne@fleckens.hu,Duerse,Nookooh5ee,615-279-1355,MasterCard,5152213097663771,480,11/2025,10/28/1997
Frederica,J,Vick,"3267 Hart Country Lane",Athens,GA,30601,US,FredericaJVick@fleckens.hu,Durry1992,Goot6lao,706-542-2114,MasterCard,5392904296712704,449,1/2023,7/16/1992
Finley,Z,Lynch,"2707 Calvin Street",Baltimore,MD,21202,US,FinleyLynch@dayrep.com,Padmings,peeCh3ooc,443-368-8341,MasterCard,5170008436367227,241,2/2027,2/20/1981