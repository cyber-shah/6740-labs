Group 22 : El Paso
Pranchal 
Liam 
# Lab 5

## Secret File
```bash
root@routerb:/etc/snort# snort -A console -q -c /etc/snort/snort.conf -i eth0
03/30-18:29:17.537939  [**] [1:1000004:1] trying to access secret file [**] [Priority: 0] {TCP} 2001:470:8cc5:3201:ba27:ebff:fe32:67:44442 -> 2001:470:8cc5:3203:eece:13ff:feea:32f3:80
03/30-18:29:17.539694  [**] [1:1000007:0] Secret File downloaded [**] [Priority: 0] {TCP} 2001:470:8cc5:3203:eece:13ff:feea:32f3:80 -> 2001:470:8cc5:3201:ba27:ebff:fe32:67:44442
```

NOT originating from us:
```bash
03/30-19:38:32.380147  [**] [1:1000002:1] access to cgi [**] [Priority: 0] {TCP} 10.10.222.1:49186 -> 10.10.152.150:80
03/30-19:38:32.396035  [**] [1:1000003:1] CGI alert [**] [Priority: 0] {TCP} 10.10.152.150:80 -> 10.10.222.1:49186
```

Output for a request that doesn't exist:
```bash
curl http://hr.ep.int.e-netsec.org/secret/corp-sec-sa22lary.xlsx
```

```bash
03/30-18:29:21.254744  [**] [1:1000004:1] trying to access secret file [**] [Priority: 0] {TCP} 2001:470:8cc5:3201:ba27:ebff:fe32:67:44444 -> 2001:470:8cc5:3203:eece:13ff:feea:32f3:80
```

### ICMP Scans
```bash
03/30-19:30:15.089258  [**] [1:1000008:0] ICMP scan detected [**] [Priority: 0] {ICMP} 10.10.152.1 -> 10.10.152.120
03/30-19:30:15.565724  [**] [1:1000008:0] ICMP scan detected [**] [Priority: 0] {IPV6-ICMP} 2001:470:8cc5:3202::1 -> 2001:470:8cc5:3202::120
```

### SSH access
```bash 
03/30-19:27:38.557091  [**] [1:1000006:1] SSH access to HR server [**] [Priority: 0] {TCP} 10.10.222.1:53246 -> 10.10.152.129:22
```
