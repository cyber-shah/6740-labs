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


Output for a request that doesn't exist:
```bash
curl http://hr.ep.int.e-netsec.org/secret/corp-sec-sa22lary.xlsx
```

```bash
03/30-18:29:21.254744  [**] [1:1000004:1] trying to access secret file [**] [Priority: 0] {TCP} 2001:470:8cc5:3201:ba27:ebff:fe32:67:44444 -> 2001:470:8cc5:3203:eece:13ff:feea:32f3:80
```
