# Submit a copy of your AIDE configuration file, fully commented.

```
# written to by fail2ban to keep track of the number of failed logins for certain users.
!/var/lib/fail2ban/fail2ban.sqlite3$
# /run/network/ is modified by ifup and ifdown. These files change whenever the pi is rebooted
# (which we had to do a few times to fix intermittent ssh connection issues).
!/run/network/.ifstate.lock$
# see above
!/run/network/ifstate.eth0$
# see above
!/run/network/ifstate.lo$
# written to by the tmux command when dealing with psuedo terminals
!/tmp/tmux-0/default$
# written to by "linux containers"
!/dev/.lxc/.*
# written to by the mail client, e.g. when fail2ban sends an email
!/var/spool/postfix/.*
```


# Submit a copy of your crontab file showing the entry for AIDE.

```
0 */4 * * * /usr/bin/aide --check --config=/etc/aide/aide.conf || (echo "aide scan failed" | mailx -s "aide scan failed" ep@hax.e-netsec.org)
```

# Submit a copy of the email alert you received when you modified a system binary.

```
From root@raspberry.localdomain Tue Feb 13 20:58:30 2024
Return-Path:
X-Original-To: ep@hax.e-netsec.org
Delivered-To: ep@hax.e-netsec.org
Received: from raspberry.localdomain (unknown [10.10.92.10])
by portal.hax.e-netsec.org (Postfix) with ESMTP id 02907241F97
for ; Tue, 13 Feb 2024 08:00:04 +0000 (UTC)
Received: by raspberry.localdomain (Postfix, from userid 0)
id 653386086B; Tue, 13 Feb 2024 08:00:03 +0000 (UTC)
To: ep@hax.e-netsec.org
Subject: aide scan failed
MIME-Version: 1.0
Content-Type: text/plain; charset="ANSI_X3.4-1968"
Content-Transfer-Encoding: 8bit
Message-Id: <20240213080003.653386086B@raspberry.localdomain>
Date: Tue, 13 Feb 2024 08:00:03 +0000 (UTC)
From: root

aide scan failed
```

# Submit a copy of the email alert that shows suspicious activities.

```
From root@raspberry.localdomain Tue Feb 13 20:18:30 2024
Return-Path:
X-Original-To: ep@hax.e-netsec.org
Delivered-To: ep@hax.e-netsec.org
Received: from raspberry.localdomain (unknown [10.10.92.10])
by portal.hax.e-netsec.org (Postfix) with ESMTP id C4678242128
for ; Tue, 13 Feb 2024 12:00:22 +0000 (UTC)
Received: by raspberry.localdomain (Postfix, from userid 0)
id C6EB86086B; Tue, 13 Feb 2024 12:00:02 +0000 (UTC)
To: ep@hax.e-netsec.org
Subject: aide scan failed
MIME-Version: 1.0
Content-Type: text/plain; charset="ANSI_X3.4-1968"
Content-Transfer-Encoding: 8bit
Message-Id: <20240213120002.C6EB86086B@raspberry.localdomain>
Date: Tue, 13 Feb 2024 12:00:02 +0000 (UTC)
From: root

aide scan failed
```

# What suspicious activities did you find?

There are files created in these places:

```
/usr/ex.dat
/usr/bin/_ts
/c2.sig
```

I don't recognize them, so I assume they have been placed by a malicious actor. /usr/bin/_ts doesn't seem to be an executable. ex.dat looks like completely random data. Same with /c2.sig.

# (Bonus) Can you find the origin of the suspicious activities? What exactly happens?

No.

# Submit a copy of your configuration changes for fail2ban

```
[DEFAULT]

# whitelist our own ip from getting banned
ignoreip = 10.10.1.10
# ban for 15 minutes
bantime  = 15m
# ban after 3 failed retries within the allowed timeframe
maxretry = 3

[sshd]
enabled = true
```

# Submit the relevant part of “auth.log” which shows failed logins and the IP ban

`cat /var/log/auth.log | grep "Failed"`:

```
Feb 13 03:40:05 raspberry sshd[1031]: Failed password for invalid user configadmin from 10.10.92.26 port 35920 ssh2
Feb 13 03:41:04 raspberry sshd[1056]: Failed password for invalid user configadmin from 10.10.92.26 port 35922 ssh2
Feb 13 04:08:34 raspberry sshd[1941]: Failed password for invalid user configadmin from 10.10.92.26 port 35986 ssh2
Feb 13 04:09:06 raspberry sshd[1949]: Failed password for invalid user configadmin from 10.10.92.26 port 35988 ssh2
Feb 13 04:25:05 raspberry sshd[2311]: Failed password for invalid user configadmin from 10.10.92.26 port 36026 ssh2
```

`cat /var/log/fail2ban.log`:

```
2024-02-13 04:08:29,603 fail2ban.filter         [1739]: INFO    [sshd] Found 10.10.92.26 - 2024-02-13 04:08:27
2024-02-13 04:08:34,820 fail2ban.filter         [1739]: INFO    [sshd] Found 10.10.92.26 - 2024-02-13 04:08:34
2024-02-13 04:09:03,423 fail2ban.filter         [1739]: INFO    [sshd] Found 10.10.92.26 - 2024-02-13 04:09:03
2024-02-13 04:09:03,499 fail2ban.actions        [1739]: NOTICE  [sshd] Ban 10.10.92.26
2024-02-13 04:09:07,743 fail2ban.filter         [1739]: INFO    [sshd] Found 10.10.92.26 - 2024-02-13 04:09:06
2024-02-13 04:24:03,106 fail2ban.actions        [1739]: NOTICE  [sshd] Unban 10.10.92.26
2024-02-13 04:25:02,402 fail2ban.filter         [1739]: INFO    [sshd] Found 10.10.92.26 - 2024-02-13 04:25:02
2024-02-13 04:25:05,478 fail2ban.filter         [1739]: INFO    [sshd] Found 10.10.92.26 - 2024-02-13 04:25:05
2024-02-13 04:25:05,606 fail2ban.actions        [1739]: NOTICE  [sshd] Ban 10.10.92.26
```


# Which IP was blocked? Which username was used for the failed login?

The ip 10.10.92.26 was blocked. The username used was `configadmin`.

# (Bonus) Configuration changes for email notification after fail2ban IP ban

Added the following to the fail2ban config:

```
[sshd]

mta = sendmail
destemail = ep@hax.e-netsec.org
senderemail = ep@hax.e-netsec.org
action = %(action_mwl)s
```

# (Bonus) Email notification after an IP ban
# (Bonus) Can you figure out what usernames and passwords were used for the SSH attack?

No.

# In your Linux router’s current AIDE configuration, name one way an attacker could prevent you from being alerted to system changes. In the worst-case scenario, if an attacker can gain root on your system, will file integrity checking suffice as a intrusion detection mechanism? If not, in what scenarios might it help secure the system?

An attacker could create a file in `/var/spool/postfix/`, which we currently whitelist entirely. Such a created file would not be detected by AIDE.

If an attacker gains root on our system, a file integrity checking program such as AIDE would not help that much. The reason is that if an attacker has root, they can use root priveledges to disable AIDE entirely, or update its database to include a "poisonied" snapshot with malware, or change AIDE's configuration to whitelist the malware.

Software like AIDE helps to secure a system in the case where attackers cannot gain root, and moreover might have a limited selection of locations to place persistent malware, all of which AIDE is hopefully checking to ensure nothing suspicious happens. It also helps in cases where the attacker is not sophisticated enough to realize AIDE is running on the system, or does not put in the effort to try and circumvent it.
